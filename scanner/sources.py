"""Источники: t.me/s с пагинацией, Telethon на все каналы + вложения, подписки (п.5)."""
import asyncio
import re

from . import log
from .extract import (TME_RE, clean_url, from_subscription, is_useless_tme, messages,
                      now_utc, sub_key, PROXY_SCHEMES, ISSUE_SCHEMES, ISSUE_RE,
                      PROXY_RE, collect_url)
from .net import fetch

try:
    from telethon import TelegramClient
    from telethon.tl.types import MessageEntityTextUrl
    TELETHON_OK = True
except ImportError:
    TELETHON_OK = False


def classify_sources(lines, cfg):
    web, embed, tg, subs = [], [], [], set()
    for src in lines:
        if not src.startswith('http'):
            continue
        if re.match(r'https?://(t\.me|telegram\.me)/', src):
            if 'LowiKForum' in src or any(x in src.lower() for x in ('chat', 'forum')):
                tg.append(src)
            elif re.search(r'/\d+$', src):
                embed.append(src)
            else:
                chan = re.sub(r'^https?://(t\.me|telegram\.me)/(s/)?', '', src).strip('/')
                web.append(f'https://t.me/s/{chan}')
        else:
            subs.add(clean_url(src))
    return web, embed, tg, subs


async def web_channel(session, sem, channel_url, cutoff, pages, cfg):
    out, urls, before = [], [], None
    for _ in range(int(pages)):
        page = channel_url + (f'?before={before}' if before else '')
        text, _ = await fetch(session, page, sem, cfg)
        if not text:
            break
        p, u, mid = messages(text, cutoff, cfg)
        out.extend(p)
        urls.extend(u)
        if not mid or (before is not None and mid >= before):
            break
        before = mid
    return out, urls


def _tg_available(cfg):
    return TELETHON_OK and cfg.telegram.api_id and cfg.telegram.session_b64


async def telethon_channels(sources, cutoff, cfg):
    """Один клиент на все каналы; темы форумов; вложения-документы. -> (items, urls)"""
    import base64
    import os

    if not _tg_available(cfg):
        log.debug('Telethon: не настроен')
        return [], []
    sf = 'tg_session'
    try:
        with open(sf + '.session', 'wb') as f:
            f.write(base64.b64decode(cfg.telegram.session_b64))
    except Exception:
        log.debug('Telethon: ошибка сессии')
        return [], []

    items, urls = [], []
    limit = int(cfg.limits.telethon_limit)
    max_bytes = int(cfg.limits.max_attachment_mb) * 1024 * 1024
    client = TelegramClient(sf, cfg.telegram.api_id, cfg.telegram.api_hash)
    docs = 0
    try:
        await client.connect()
        if not await client.is_user_authorized():
            log.debug('Telethon: сессия не авторизована')
            return [], []
        for src in sources:
            m = re.match(r'https?://t\.me/(?:c/)?([a-zA-Z0-9_]+)(?:/(\d+))?', src)
            if not m:
                continue
            chat, topic = m.group(1), int(m.group(2)) if m.group(2) else None
            if '/c/' in src:
                try:
                    chat = int(f'-100{chat}')
                except ValueError:
                    pass
            try:
                entity = await client.get_entity(chat)
            except Exception:
                log.debug('Telethon: источник недоступен')
                continue
            kw = {'reply_to': topic} if topic and getattr(entity, 'forum', False) else {}
            try:
                async for msg in client.iter_messages(entity, limit=limit, **kw):
                    if not msg.date:
                        continue
                    dt = msg.date if msg.date.tzinfo else msg.date.replace(tzinfo=__import__('datetime').timezone.utc)
                    if dt < cutoff:
                        break
                    text = msg.text or msg.message or ''
                    for mm in PROXY_RE.finditer(text):
                        items.append((clean_url(mm.group(0)), dt, src))
                    for mm in ISSUE_RE.finditer(text):
                        from .extract import ISSUE_URLS
                        ISSUE_URLS.add(clean_url(mm.group(0)))
                    for mm in __import__('scanner.extract', fromlist=['URL_RE']).URL_RE.finditer(text):
                        collect_url(mm.group(0), urls, cfg)
                    for ent in (msg.entities or []):
                        if isinstance(ent, MessageEntityTextUrl) and ent.url:
                            u = clean_url(ent.url)
                            if any(u.lower().startswith(s + '://') for s in PROXY_SCHEMES):
                                items.append((u, dt, src))
                            else:
                                collect_url(ent.url, urls, cfg)
                    # вложения: каналы часто выкладывают ключи .txt-файлом
                    if cfg.telethon.attachments and getattr(msg, 'document', None):
                        size = getattr(msg.document, 'size', 0) or 0
                        if 0 < size <= max_bytes:
                            try:
                                blob = await client.download_media(msg, bytes)
                                if blob:
                                    body = blob.decode('utf-8', errors='ignore')
                                    for u in from_subscription(body, cfg):
                                        items.append((u, dt, src))
                                    docs += 1
                            except Exception:
                                pass
            except Exception:
                log.debug('Telethon: ошибка чтения источника')
    except Exception:
        log.debug('Telethon: ошибка соединения')
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
        try:
            os.remove(sf + '.session')
        except OSError:
            pass
    log.debug(f'Telethon: источников {len(sources)}, ссылок {len(items)}, вложений {docs}')
    return items, urls


async def subscription(url, session, sem, visited, cutoff, cfg, cache):
    """-> [(uri, дата, источник)]"""
    key = sub_key(url)
    if key in visited:
        return []
    visited.add(key)
    if url.startswith('happ://'):
        return [(url, now_utc(), url)]
    if not url.startswith(('http://', 'https://')) or is_useless_tme(url):
        return []

    if 't.me/' in url or 'telegram.me/' in url:
        m = TME_RE.match(url)
        if not m:
            return []
        chan, mid = m.group(1), m.group(2)
        if mid:
            label = f'https://t.me/{chan}/{mid}'
            text, _ = await fetch(session, label + '?embed=1&mode=tme', sem, cfg)
            if not text:
                return []
            p, _, _ = messages(text, cutoff, cfg)
            return [(u, dt, label) for u, dt in p]
        label = f'https://t.me/s/{chan}'
        p, _ = await web_channel(session, sem, label, cutoff, cfg.limits.tme_sub_pages, cfg)
        return [(u, dt, label) for u, dt in p]

    cached = cache.fresh_uris(url) if cache else None
    text, not_modified = await fetch(session, url, sem, cfg, cache=cache)
    if not_modified and cached is not None:
        return [(u, now_utc(), url) for u in cached]
    if not text:
        return []

    reuse = cache.seen_content(text) if cache else None
    if reuse is not None:
        uris = reuse
    else:
        uris = from_subscription(text, cfg)
        if cache:
            cache.put_content(text, uris)
    if cache:
        cache.put_http(url, '', '', uris)
    now = now_utc()
    return [(u, now, url) for u in uris]
