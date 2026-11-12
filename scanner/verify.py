import asyncio
import gzip
import json
import os
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

import aiohttp
import yaml

from . import log
from .net import ping


async def l0_tcp(endpoints, cfg, cache, sem):
    """-> {(host, port): rtt|None}. Кэш с TTL, каждый endpoint один раз."""
    out, todo = {}, []
    for hp in endpoints:
        e = cache.ping.get(f'{hp[0]}:{hp[1]}') if cache else None
        fresh = False
        if e:
            ttl = float(cfg.cache.ping_ok_ttl_hours if e.get('ok') else cfg.cache.ping_fail_ttl_hours)
            fresh = time.time() - e.get('ts', 0) <= ttl * 3600
        if fresh:
            out[hp] = e.get('rtt') if e.get('ok') else None
        else:
            todo.append(hp)
    log.debug(f'🌐 L0: всего {len(endpoints)}, из кэша {len(out)}, пингуем {len(todo)}')

    async def one(hp):
        t0 = time.perf_counter()
        ok = await ping(hp[0], hp[1], sem, float(cfg.timeouts.ping))
        rtt = (time.perf_counter() - t0) if ok else None
        if cache:
            cache.ping_put(hp[0], hp[1], rtt)
        return hp, rtt

    if todo:
        for hp, rtt in await asyncio.gather(*(one(hp) for hp in todo)):
            out[hp] = rtt
    return out


async def l1_tls(items, cfg):
    """items: [(key, host, port, sni)] -> {key: bool}. Только TLS-конфиги."""
    sem = asyncio.Semaphore(int(cfg.concurrency.tls))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    async def one(key, host, port, sni):
        async with sem:
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(host, int(port), ssl=ctx, server_hostname=sni or None),
                    timeout=float(cfg.timeouts.tls))
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                return key, True
            except asyncio.CancelledError:
                raise
            except Exception:
                return key, False

    res = await asyncio.gather(*(one(*x) for x in items))
    ok = sum(1 for _, v in res if v)
    log.debug(f'🔐 L1 TLS: проверено {len(items)}, рукопожатие прошло {ok}')
    return dict(res)


async def _ensure_core(cfg, session):
    """Скачивает mihomo последней версии. Возвращает путь или None."""
    bindir = Path(cfg.cache.dir) / 'bin'
    bindir.mkdir(parents=True, exist_ok=True)
    binary = bindir / 'mihomo'
    if binary.exists() and os.access(binary, os.X_OK):
        return str(binary)
    try:
        async with session.get(cfg.verify.core_api,
                               headers={'Accept': 'application/vnd.github+json'},
                               timeout=aiohttp.ClientTimeout(total=30)) as r:
            if r.status != 200:
                log.debug(f'⚠️ L2: релиз mihomo недоступен ({r.status})')
                return None
            data = await r.json()
        asset = None
        for a in data.get('assets', []):
            n = a.get('name', '')
            if n.startswith('mihomo-linux-amd64') and n.endswith('.gz') and 'compatible' not in n:
                asset = a
                break
        if not asset:
            log.debug('⚠️ L2: подходящий бинарник не найден')
            return None
        async with session.get(asset['browser_download_url'],
                               timeout=aiohttp.ClientTimeout(total=120)) as r:
            if r.status != 200:
                return None
            blob = await r.read()
        binary.write_bytes(gzip.decompress(blob))
        binary.chmod(0o755)
        log.debug('⬇️ L2: mihomo скачан')
        return str(binary)
    except Exception as e:
        log.debug(f'⚠️ L2: не удалось получить ядро ({type(e).__name__})')
        return None


async def l2_core(named, cfg, session):
    """named: [(name, clash_dict)] -> (delays, geo, l3_tg, l3_yt).

    L2 — задержка через ядро (test_url).
    L3 — доступность Telegram/YouTube через ТО ЖЕ ядро, с ретраями.
    Любой сбой -> пустые словари, пайплайн продолжает работу на L1.
    """
    if not named:
        return {}, {}, {}, {}
    binary = await _ensure_core(cfg, session)
    if not binary:
        return {}, {}, {}, {}

    tmp = Path(tempfile.mkdtemp(prefix='mihomo-'))
    conf = {
        'mixed-port': int(cfg.verify.mixed_port),
        'external-controller': cfg.verify.controller,
        'mode': 'global',
        'log-level': 'silent',
        'proxies': [p for _, p in named],
        'proxy-groups': [{'name': 'GLOBAL', 'type': 'select',
                          'proxies': [n for n, _ in named]}],
        'rules': ['MATCH,GLOBAL'],
    }
    (tmp / 'config.yaml').write_text(
        yaml.dump(conf, allow_unicode=True, sort_keys=False), encoding='utf-8')

    proc = None
    delays, geo = {}, {}
    l3_tg, l3_yt = {}, {}
    base = f"http://{cfg.verify.controller}"
    try:
        proc = subprocess.Popen([binary, '-d', str(tmp), '-f', str(tmp / 'config.yaml')],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as api:
            for _ in range(40):
                try:
                    async with api.get(base + '/version') as r:
                        if r.status == 200:
                            break
                except Exception:
                    pass
                await asyncio.sleep(0.25)
            else:
                log.debug('⚠️ L2: ядро не поднялось')
                return {}, {}, {}, {}

            sem = asyncio.Semaphore(int(cfg.concurrency.core))
            test_url = cfg.verify.test_url
            tmo = int(cfg.timeouts.core_delay_ms)

            async def _delay(name, url, timeout_ms):
                u = f"{base}/proxies/{quote(name, safe='')}/delay"
                async with api.get(u, params={'url': url, 'timeout': str(timeout_ms)}) as r:
                    body = await r.json(content_type=None)
                    d = body.get('delay') if isinstance(body, dict) else None
                    return int(d) if isinstance(d, int) and d > 0 else None

            # ---------- L2 ----------
            async def delay(name):
                async with sem:
                    try:
                        return name, await _delay(name, test_url, tmo)
                    except Exception:
                        return name, None

            for name, d in await asyncio.gather(*(delay(n) for n, _ in named)):
                delays[name] = d
            ok = sum(1 for v in delays.values() if v)
            log.info(f'[L2] через ядро проверено {len(named)}, реально работают {ok}')

            # ---------- L3: Telegram / YouTube с ретраями ----------
            l3cfg = getattr(cfg.verify, 'l3', None)
            if l3cfg and getattr(l3cfg, 'enabled', False):
                tg_url = getattr(l3cfg, 'telegram', '') or ''
                yt_url = getattr(l3cfg, 'youtube', '') or ''
                l3_tmo = int(getattr(l3cfg, 'timeout_ms', 12000))
                l3_retries = max(1, int(getattr(l3cfg, 'retries', 2)))
                only_alive = bool(getattr(l3cfg, 'only_alive', True))
                targets = [n for n, _ in named if delays.get(n) or not only_alive]

                async def probe_service(name, url):
                    """Один сервис, несколько попыток. Возвращает True/False."""
                    for attempt in range(l3_retries):
                        try:
                            d = await _delay(name, url, l3_tmo)
                            if d is not None:
                                return True
                        except Exception:
                            pass
                        if attempt < l3_retries - 1:
                            await asyncio.sleep(0.5)
                    return False

                async def l3_check(name):
                    async with sem:
                        tg = await probe_service(name, tg_url) if tg_url else None
                        yt = await probe_service(name, yt_url) if yt_url else None
                        return name, tg, yt

                if targets and (tg_url or yt_url):
                    for name, tg, yt in await asyncio.gather(*(l3_check(n) for n in targets)):
                        if tg is not None:
                            l3_tg[name] = tg
                        if yt is not None:
                            l3_yt[name] = yt
                    tg_ok = sum(1 for v in l3_tg.values() if v)
                    yt_ok = sum(1 for v in l3_yt.values() if v)
                    log.info(f'[L3] проверено {len(targets)} → '
                             f'TG {tg_ok}/{len(l3_tg)} | YT {yt_ok}/{len(l3_yt)}')

            # ---------- Geo (опционально) ----------
            top = int(cfg.verify.geo_top or 0)
            if top > 0:
                alive = sorted([(n, d) for n, d in delays.items() if d], key=lambda x: x[1])[:top]
                proxy = f"http://127.0.0.1:{int(cfg.verify.mixed_port)}"
                for name, _d in alive:
                    try:
                        async with api.put(base + '/proxies/GLOBAL', json={'name': name}):
                            pass
                        async with api.get(cfg.verify.geo_url, proxy=proxy,
                                           timeout=aiohttp.ClientTimeout(total=12)) as r:
                            j = await r.json(content_type=None)
                            ip = j.get('ip')
                        if ip:
                            async with api.get(f'http://ip-api.com/json/{ip}?fields=countryCode',
                                               timeout=aiohttp.ClientTimeout(total=10)) as r:
                                j2 = await r.json(content_type=None)
                                cc = j2.get('countryCode')
                                if cc:
                                    geo[name] = cc
                    except Exception:
                        continue
                log.debug(f'🌍 L2: страна определена для {len(geo)} прокси')
    except Exception as e:
        log.debug(f'⚠️ L2/L3: сбой ({type(e).__name__})')
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
    return delays, geo, l3_tg, l3_yt
