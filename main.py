import os
import re
import html
import base64
import asyncio
import yaml
import json
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlparse, urlsplit
from bs4 import BeautifulSoup
import aiohttp

try:
    from telethon import TelegramClient
    from telethon.tl.types import MessageEntityUrl, MessageEntityTextUrl
    TELETHON_OK = True
except ImportError:
    TELETHON_OK = False

SOURCES_FILE = 'sources.txt'
OUT_TXT = 'proxy.txt'
OUT_YAML = 'proxy.yaml'
OUT_ALL_TXT = 'proxy-all.txt'
OUT_ALL_YAML = 'proxy-all.yaml'
MAX_DAYS = 10
TIMEOUT = aiohttp.ClientTimeout(total=12, connect=7)
MAX_CONCURRENT_HTTP = 50
MAX_CONCURRENT_PING = 500

# 0 = без лимита; N = не больше N вариантов на один host:port (после дедупа по конфигу)
MAX_PER_ENDPOINT = 3

API_ID = int(os.getenv('TELEGRAM_API_ID', '0'))
API_HASH = os.getenv('TELEGRAM_API_HASH', '')
SESSION_B64 = os.getenv('TELEGRAM_SESSION', '')

PROXY_SCHEMES = ['vless', 'vmess', 'ss', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'happ']
_SCHEMES_ALT = '|'.join(PROXY_SCHEMES)
_URL_CHARS = r"[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]"
# Останавливается перед следующей схемой -> склеенные ссылки извлекаются по отдельности
PROXY_REGEX = re.compile(
    r'(?:' + _SCHEMES_ALT + r')://(?:(?!(?:' + _SCHEMES_ALT + r')://)' + _URL_CHARS + r')+',
    re.IGNORECASE)
URL_REGEX = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)

BLACKLIST_DOMAINS = [
    'youtube.com', 'youtu.be', 'instagram.com', 'twitter.com', 'x.com',
    'vk.com', 'ok.ru', 'pikabu.ru', 'habr.com', 'dzen.ru', 'yandex.ru',
    'mail.ru', 'rambler.ru', 'meduza.io', 'kommersant.ru', 'cnews.ru',
    'iz.ru', 'techradar.com', 'openai.com', 'sozd.duma.gov.ru',
    'playgta5.com', 'mrbeast.nocp.uz', 'cloud.mail.ru', 'max.ru',
    'git.a9fm.best', 'ria.ru', 'lenta.ru', 'rbc.ru', 'vedomosti.ru',
    'tass.ru', 'h1cloud.net'
]

STICKY_WORDS = ['Gemini', 'Gemini:', 'Claude', 'ChatGPT']

WHITELIST_ROOTS = "бел спис обход авто глушил lte 4g 5g mobil ркт ркн rkn front disgu wl white-list whitelist notorgames aetris clearq owpn cyberportal dismissaltree"

ENABLE_VLESS = True
ENABLE_VMESS = True
ENABLE_SS = True
ENABLE_TROJAN = True
ENABLE_HYSTERIA = True
ENABLE_HYSTERIA2 = True
ENABLE_TUIC = True

VALID_CIPHERS = {
    'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'aes-128-cfb', 'aes-192-cfb',
    'aes-256-cfb', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'rc4-md5',
    'chacha20', 'chacha20-ietf', 'xchacha20', 'chacha20-ietf-poly1305',
    'xchacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305', 'none', 'plain', 'dummy', 'auto'
}
VALID_NETWORKS = {'tcp', 'ws', 'grpc', 'h2', 'http', 'httpupgrade', 'raw', 'xhttp'}
VALID_FINGERPRINTS = {'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'qq'}
VALID_FLOWS = {'xtls-rprx-vision', 'xtls-rprx-vision-udp443'}
UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
SID_RE = re.compile(r'^(?:[0-9a-fA-F]{2}){0,8}$')

_KEYWORD_ROOTS = [w.lower() for w in WHITELIST_ROOTS.split() if w]

# --- дедуп по конфигу ---
IGNORED_PARAMS = {'fp', 'alpn', 'extra', 'headertype', 'encryption', 'allowinsecure',
                  'insecure', 'fm', 'packetencoding', 'spx', 'ed'}
DEDUP_SCHEMES = {'vless', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic'}
# True: vless-ссылки на один и тот же сервер, отличающиеся только uuid/short-id, считаются дублем
DEDUP_IGNORE_USER = True

_AMP_RE = re.compile(r'&(?:amp|#0*38|#x0*26);', re.I)
_RAW_RE = re.compile(r'([?&]type=)raw(?=[&#]|$)', re.I)

DEBUG = True

def debug_log(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")

def decode_base64(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding: s += '=' * (4 - padding)
    try: return base64.b64decode(s).decode('utf-8', errors='ignore')
    except: return ""

def is_valid_url(url):
    try:
        r = urlparse(url)
        if not all([r.scheme, r.netloc]): return False
        if r.scheme == 'tg': return False
        if any(d in r.netloc for d in BLACKLIST_DOMAINS): return False
        return True
    except: return False

def is_useless_tme(url):
    if not ('t.me' in url or 'telegram.me' in url): return False
    if '/proxy?' in url or '/webproxy?' in url: return True
    if '/+' in url.split('//', 1)[-1][:10]: return True
    path = urlparse(url).path.strip('/')
    if '/' not in path and path.lower().endswith('bot'): return True
    return False

def split_glued(url):
    base = 8 if url.startswith('https://') else 7
    rest = url[base:]
    for proto in ['https://', 'http://']:
        idx = rest.find(proto)
        if idx > 0:
            char_before = rest[idx-1]
            if char_before != '/':
                return url[:base + idx]
    if url.count('@') >= 2:
        head = rest
        if '@' in head:
            at_idx = head.index('@')
            part_before_at = head[:at_idx]
            if '/' not in part_before_at and ':' not in part_before_at:
                return url[:base + at_idx]
    return url

def remove_sticky_words(url):
    for word in STICKY_WORDS:
        if url.endswith(word):
            url = url[:-len(word)]
    return url.rstrip('/')

def clean_url(url):
    """Очистка URL: &amp; -> &, имя после # кодируется (а не режется), type=raw -> tcp"""
    # &amp; / &amp;amp; -> &
    while _AMP_RE.search(url):
        url = _AMP_RE.sub('&', url)
    # не-ASCII до '#' (склеенный мусор) режем как раньше; имя после '#' кодируем в %XX
    head, sep, frag = url.partition('#')
    for i, c in enumerate(head):
        if ord(c) > 127:
            head, sep, frag = head[:i], '', ''
            break
    frag = quote(frag, safe="-._~:/?#[]@!$&'()*+,;=%")
    if not frag:
        sep = ''
    url = head + sep + frag
    # raw = новое имя tcp в Xray
    url = _RAW_RE.sub(r'\1tcp', url)
    while url.endswith(')') and url.count(')') > url.count('('): url = url[:-1]
    url = split_glued(url.rstrip('.,;:!?'))
    url = remove_sticky_words(url)
    return url

def collect_url(raw, urls):
    u = clean_url(raw)
    if not u: return
    if 't.me' in u or 'telegram.me' in u:
        if not is_useless_tme(u): urls.append(u)
    elif is_valid_url(u):
        urls.append(u)

def make_names_unique(proxies):
    used = {}
    renamed = 0
    for p in proxies:
        name = (p.get('name') or '').strip()
        if not name:
            name = f"{p.get('type', 'proxy')}-{p.get('server', 'unknown')}:{p.get('port', 0)}"
        base_name = name
        if name in used:
            used[name] += 1
            name = f"{base_name} #{used[name]}"
            renamed += 1
        else:
            used[name] = 1
        p['name'] = name
    if renamed:
        debug_log(f"🏷️ Переименовано дубликатов имён: {renamed}")
    return proxies

def deduplicate_proxies(proxies):
    """Убирает только полные дубликаты строк"""
    seen = set()
    result = []
    dupes = 0

    for proxy in proxies:
        if not proxy:
            continue
        if proxy in seen:
            dupes += 1
            continue
        seen.add(proxy)
        result.append(proxy)

    if dupes:
        debug_log(f"🔁 Дубликатов удалено: {dupes}")

    return result

def _uri_parts(uri):
    try:
        u = urlsplit(uri)
        q = {k.lower(): v for k, v in parse_qsl(u.query)}
        return (u.scheme.lower(), u.username or '', u.password or '',
                (u.hostname or '').lower(), u.port or 0,
                u.path.rstrip('/'), q, unquote(u.fragment))
    except ValueError:
        return None

def config_key(uri):
    p = _uri_parts(uri)
    if not p or p[0] not in DEDUP_SCHEMES or not p[3]:
        return uri  # vmess/ss/happ и непарсящееся: только точные дубли
    scheme, user, pwd, host, port, path, q, _ = p
    q = {k: v for k, v in q.items() if v and k not in IGNORED_PARAMS}
    if q.get('type') == 'raw': q['type'] = 'tcp'
    q.setdefault('type', 'tcp')
    if q.get('mode') == 'auto': del q['mode']
    # TLS: sni и host - одно и то же, если задан только один из них или они равны
    if q.get('security') == 'tls':
        eff = q.get('sni') or q.get('host')
        if eff:
            q['sni'] = eff
            if q.get('host') == eff: q.pop('host')
    # чистый tcp: path/host ни на что не влияют
    if q['type'] == 'tcp':
        q.pop('path', None); q.pop('host', None)
    # тот же сервер с другим uuid / short-id - для списка это дубль
    if DEDUP_IGNORE_USER and scheme == 'vless':
        user = ''
        if q.get('security') == 'reality': q.pop('sid', None)
    return (scheme, user, pwd, host, port, path, tuple(sorted(q.items())))

def _rank(uri):
    """Из дублей берём тот, чьё имя проходит WL-фильтр; затем более длинное имя"""
    p = _uri_parts(uri)
    if not p: return (False, 0)
    return (matches_roots({'name': p[7], 'server': p[3], 'sni': p[6].get('sni', '')}), len(p[7]))

def dedupe_by_config(uris):
    groups = {}
    for u in sorted(set(uris)):  # sorted -> результат детерминирован
        groups.setdefault(config_key(u), []).append(u)
    result = [max(g, key=_rank) for g in groups.values()]
    if MAX_PER_ENDPOINT > 0:
        per, capped = {}, []
        for u in sorted(result, key=_rank, reverse=True):
            p = _uri_parts(u)
            ep = (p[3], p[4]) if p and p[3] else u
            per[ep] = per.get(ep, 0) + 1
            if per[ep] <= MAX_PER_ENDPOINT:
                capped.append(u)
        result = capped
    return result

def matches_roots(p):
    searchable = ' '.join([
        str(p.get('name', '')),
        str(p.get('server', '')),
        str(p.get('sni', '')),
        str(p.get('server-name', '')),
    ]).lower()
    return any(root in searchable for root in _KEYWORD_ROOTS)

def get_enabled_protocols():
    protocols = set()
    if ENABLE_VLESS: protocols.add('vless')
    if ENABLE_VMESS: protocols.add('vmess')
    if ENABLE_SS: protocols.add('ss')
    if ENABLE_TROJAN: protocols.add('trojan')
    if ENABLE_HYSTERIA: protocols.add('hysteria')
    if ENABLE_HYSTERIA2: protocols.add('hysteria2')
    if ENABLE_TUIC: protocols.add('tuic')
    return protocols

def filter_by_protocol(proxies):
    enabled = get_enabled_protocols()
    stats = {'total_in': len(proxies), 'by_protocol': {}, 'dropped': 0, 'total_out': 0}
    result = []
    for p in proxies:
        ptype = p.get('type', '')
        if ptype not in enabled:
            stats['by_protocol'][ptype] = stats['by_protocol'].get(ptype, 0) + 1
            stats['dropped'] += 1
            continue
        result.append(p)
    stats['total_out'] = len(result)
    return result, stats

def validate_all(proxies):
    valid = []
    invalid = 0
    for idx, p in enumerate(proxies):
        ok, reason = validate_proxy(p)
        if ok:
            valid.append(p)
        else:
            invalid += 1
            if invalid <= 10:
                debug_log(f"🚫 [{idx}] Отброшен: {p.get('name','?')[:35]} | {reason}")
    if invalid:
        debug_log(f"🚫 Всего отброшено невалидных: {invalid}")
    return valid

def sanitize_proxy(p):
    net = p.get('network')
    if net not in VALID_NETWORKS:
        p['network'] = 'tcp'
        net = 'tcp'
    if net != 'ws' and 'ws-opts' in p: del p['ws-opts']
    if net != 'grpc' and 'grpc-opts' in p: del p['grpc-opts']
    if net != 'h2' and 'h2-opts' in p: del p['h2-opts']
    if net != 'http' and 'http-opts' in p: del p['http-opts']
    if net != 'xhttp' and 'xhttp-opts' in p: del p['xhttp-opts']
    if 'ws-opts' in p and isinstance(p['ws-opts'], dict):
        path = p['ws-opts'].get('path', '/')
        if not isinstance(path, str) or not path.startswith('/'):
            p['ws-opts']['path'] = '/'
    fp = p.get('client-fingerprint')
    if fp and fp not in VALID_FINGERPRINTS:
        p['client-fingerprint'] = 'chrome'
    elif not fp and p.get('tls'):
        p['client-fingerprint'] = 'chrome'
    flow = p.get('flow')
    if flow and (flow not in VALID_FLOWS or p.get('type') != 'vless'):
        del p['flow']
    if p.get('tls'):
        sn = p.get('server-name') or p.get('servername')
        if not sn:
            p['server-name'] = p.get('server', '')
        p.pop('servername', None)
    uuid = p.get('uuid', '')
    if isinstance(uuid, str):
        cleaned = re.sub(r'[^0-9a-fA-F-]', '', uuid)
        p['uuid'] = cleaned
    return p

def validate_proxy(p):
    if not isinstance(p, dict):
        return False, 'not dict'
    ptype = p.get('type')
    server = p.get('server')
    port = p.get('port')
    name = p.get('name')

    if not name or not isinstance(name, str):
        return False, 'empty name'
    if not server or not isinstance(server, str):
        return False, 'empty server'
    if any(c.isspace() for c in server):
        return False, 'space in server'
    if '/' in server or '%' in server or '@' in server:
        return False, 'bad char in server'
    if not isinstance(port, int) or not (1 <= port <= 65535):
        return False, 'bad port'

    if ptype in ('vless', 'vmess'):
        uuid = p.get('uuid', '')
        if not uuid or not UUID_RE.match(uuid):
            return False, 'bad uuid format'
        if p.get('network') not in VALID_NETWORKS:
            return False, 'bad network'
        if ptype == 'vmess':
            if not isinstance(p.get('alterId'), int) or p.get('alterId') < 0:
                return False, 'bad alterId'
            if p.get('cipher') not in ('auto', 'aes-128-gcm', 'chacha20-poly1305', 'none'):
                return False, 'bad vmess cipher'
        if ptype == 'vless' and p.get('flow') and not p.get('tls'):
            return False, 'flow without tls'
    elif ptype == 'trojan':
        if not p.get('password'):
            return False, 'empty password'
    elif ptype == 'ss':
        if not p.get('password'):
            return False, 'empty password'
        if p.get('cipher') not in VALID_CIPHERS:
            return False, f"bad cipher"
    elif ptype in ('hysteria', 'hysteria2'):
        if not p.get('password'):
            return False, 'empty password'
    elif ptype == 'tuic':
        if not p.get('uuid') or not UUID_RE.match(p.get('uuid', '')):
            return False, 'bad uuid'
        if not p.get('password'):
            return False, 'empty password'
    else:
        return False, f'unknown type'

    if 'reality-opts' in p:
        ro = p['reality-opts']
        if not ro.get('public-key'):
            return False, 'reality without pbk'
        sid = ro.get('short-id', '')
        if sid and not SID_RE.match(str(sid)):
            return False, 'bad short-id'
        if not p.get('server-name'):
            return False, 'reality without sni'

    return True, ''

def extract_from_element(element):
    proxies, urls = [], []
    if hasattr(element, 'find_all'):
        for a in element.find_all('a', href=True):
            href = a['href'].strip()
            if any(href.startswith(f"{s}://") for s in PROXY_SCHEMES):
                proxies.append(clean_url(href))
            elif href.startswith('http'):
                collect_url(href, urls)
    text = element.get_text() if hasattr(element, 'get_text') else str(element)
    proxies.extend([clean_url(m.group(0)) for m in PROXY_REGEX.finditer(text)])
    for m in URL_REGEX.finditer(text):
        collect_url(m.group(0), urls)
    return list(set(proxies)), list(set(urls))

async def fetch(session, url, sem, retry_count=2):
    async with sem:
        try:
            if not url.startswith(('http://', 'https://')): return ""
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8',
                'Connection': 'keep-alive',
            }
            if 'kfwl.lol' in url:
                headers['Referer'] = 'https://t.me/'
            timeout = TIMEOUT
            problem_domains = ['kfwl.lol', 'pozor.bond', 'atlanta-subs.ru', 'astra-sub.com', 'taurus-sync.com', 'net4.su']
            if any(d in url for d in problem_domains):
                timeout = aiohttp.ClientTimeout(total=30, connect=10)
            for attempt in range(retry_count + 1):
                try:
                    async with session.get(url, headers=headers, allow_redirects=True, ssl=False, timeout=timeout) as resp:
                        if resp.status == 200:
                            data = await resp.read()
                            text = data.decode('utf-8', errors='ignore')
                            debug_log(f"✓ {url[:80]}: {len(text)} симв.")
                            return text
                        elif resp.status in [403, 429, 503]:
                            if attempt < retry_count:
                                await asyncio.sleep(2 * (attempt + 1))
                                continue
                            return ""
                        else:
                            return ""
                except (asyncio.TimeoutError, aiohttp.ServerTimeoutError):
                    if attempt < retry_count:
                        await asyncio.sleep(2 * (attempt + 1))
                        continue
                    return ""
                except Exception:
                    if attempt < retry_count:
                        await asyncio.sleep(1)
                        continue
                    return ""
        except Exception:
            pass
        return ""

def extract_messages_data(html_content, cutoff_date):
    soup = BeautifulSoup(html_content, 'html.parser')
    messages = soup.find_all('div', class_='tgme_widget_message')
    p, u = [], []
    for msg in messages:
        time_tag = msg.find('time')
        if time_tag and time_tag.get('datetime'):
            try:
                dt = datetime.fromisoformat(time_tag['datetime'].replace('Z', '+00:00'))
                if dt < cutoff_date: continue
            except: pass
        px, ur = extract_from_element(msg)
        p.extend(px); u.extend(ur)
    debug_log(f"Найдено сообщений: {len(messages)}")
    return p, u

async def parse_with_telethon(source_url, cutoff_date):
    if not SESSION_B64 or not TELETHON_OK or API_ID == 0:
        debug_log("Telethon не настроен")
        return [], []
    match = re.match(r'https?://t\.me/(?:c/)?([a-zA-Z0-9_]+)(?:/(\d+))?', source_url)
    if not match: return [], []
    chat_id = match.group(1)
    topic_id = int(match.group(2)) if match.group(2) else None
    if '/c/' in source_url:
        try: chat_id = int(f"-100{chat_id}")
        except: pass
    session_file = 'tg_session'
    try:
        session_data = base64.b64decode(SESSION_B64)
        with open(session_file + '.session', 'wb') as f:
            f.write(session_data)
    except Exception:
        return [], []
    proxies, urls = [], []
    client = None
    try:
        client = TelegramClient(session_file, API_ID, API_HASH)
        await client.connect()
        if not await client.is_user_authorized():
            return [], []
        try:
            entity = await client.get_entity(chat_id)
        except Exception:
            return [], []
        msg_count = 0
        try:
            async for msg in client.iter_messages(entity, limit=300):
                if not msg.date: continue
                msg_date = msg.date.replace(tzinfo=timezone.utc)
                if msg_date < cutoff_date: break
                msg_count += 1
                text = msg.text or msg.message or ''
                for m in PROXY_REGEX.finditer(text):
                    proxies.append(clean_url(m.group(0)))
                for m in URL_REGEX.finditer(text):
                    collect_url(m.group(0), urls)
                if msg.entities:
                    for ent in msg.entities:
                        if isinstance(ent, MessageEntityTextUrl) and ent.url:
                            u = clean_url(ent.url)
                            if any(u.startswith(f"{s}://") for s in PROXY_SCHEMES):
                                proxies.append(u)
                            else:
                                collect_url(ent.url, urls)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        if client:
            try: await client.disconnect()
            except: pass
        try: os.remove(session_file + '.session')
        except: pass
    return list(set(proxies)), list(set(urls))

async def process_subscription(url, session, sem, visited):
    if url in visited: return []
    visited.add(url)
    if url.startswith('happ://'): return [url]
    if not url.startswith(('http://', 'https://')): return []
    if is_useless_tme(url): return []
    if 'kfwl.lol' in url:
        text = await fetch(session, url, sem, retry_count=1)
        if not text or len(text) < 50: return []
        decoded = decode_base64(text)
        search_text = decoded if decoded and len(decoded) > 50 else text
        found = [clean_url(p) for p in PROXY_REGEX.findall(search_text)]
        if found: debug_log(f"✓ {len(found)} прокси в {url[:60]}")
        return found
    text = await fetch(session, url, sem)
    if not text: return []
    decoded = decode_base64(text)
    search_text = decoded if decoded and len(decoded) > 50 else text
    found = [clean_url(p) for p in PROXY_REGEX.findall(search_text)]
    if found: debug_log(f"✓ {len(found)} прокси в {url[:60]}")
    return found

async def check_proxy_tcp(host, port, sem):
    async with sem:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=2.0)
            w.close(); await w.wait_closed()
            return True
        except: return False

def is_valid_hex(s):
    return bool(s) and bool(SID_RE.match(s))

def parse_uri_for_clash(uri):
    def safe_int(s, default=0):
        s = s.split('/')[0].split('#')[0].split('?')[0].strip()
        try: return int(s)
        except: return default
    def safe_str(values_list, default=''):
        if not values_list: return default
        val = values_list[0]
        return val if val else default
    try:
        s, rest = uri.split('://', 1)
        s = s.lower()
        if s == 'happ': return None

        if s == 'vless':
            uuid, rest2 = rest.split('@', 1)
            if '#' in rest2:
                hp_params, name_part = rest2.split('#', 1)
            else:
                hp_params, name_part = rest2, ''
            if '?' in hp_params:
                hp, query_str = hp_params.split('?', 1)
            else:
                hp, query_str = hp_params, ''
            if '/' in hp: hp = hp.split('/')[0]
            if ':' not in hp: return None
            h, p_str = hp.split(':', 1)
            p = safe_int(p_str)
            if not p: return None
            name = unquote(name_part) if name_part else f"VLESS-{h}"
            q = parse_qs(query_str) if query_str else {}
            nt = safe_str(q.get('type'), 'tcp')
            if nt == 'raw': nt = 'tcp'
            res = {
                'name': name, 'type': 'vless', 'server': h, 'port': p,
                'uuid': uuid, 'network': nt, 'udp': True,
            }
            security = safe_str(q.get('security'), '')
            sni = safe_str(q.get('sni'), '')
            fp = safe_str(q.get('fp'), '')
            flow = safe_str(q.get('flow'), '')
            host_header = safe_str(q.get('host'), '')
            if security == 'reality':
                pbk = safe_str(q.get('pbk'), '')
                sid = safe_str(q.get('sid'), '').strip()
                if not pbk: return None
                res['tls'] = True
                res['server-name'] = sni if sni else h
                reality_opts = {'public-key': pbk}
                if sid and is_valid_hex(sid):
                    reality_opts['short-id'] = sid
                elif sid: return None
                res['reality-opts'] = reality_opts
                if fp: res['client-fingerprint'] = fp
                if flow: res['flow'] = flow
            elif security == 'tls':
                res['tls'] = True
                res['server-name'] = sni if sni else h
                if fp: res['client-fingerprint'] = fp
            if nt == 'ws':
                path = safe_str(q.get('path'), '/')
                ws_opts = {'path': unquote(path) if unquote(path).startswith('/') else '/' + unquote(path)}
                if host_header:
                    ws_opts['headers'] = {'Host': host_header}
                res['ws-opts'] = ws_opts
            elif nt == 'grpc':
                service = safe_str(q.get('serviceName'), '')
                if service:
                    res['grpc-opts'] = {'grpc-service-name': service}
            elif nt == 'xhttp':
                res['network'] = 'xhttp'
            return res

        elif s == 'vmess':
            try:
                d = json.loads(decode_base64(rest))
                if not isinstance(d, dict): return None
                res = {
                    'name': d.get('ps', f"VM-{d.get('add', 'unknown')}"),
                    'type': 'vmess', 'server': d.get('add'),
                    'port': safe_int(str(d.get('port', 0))),
                    'uuid': d.get('id', ''),
                    'alterId': safe_int(str(d.get('aid', 0))),
                    'cipher': 'auto',
                    'tls': d.get('tls') == 'tls',
                    'network': d.get('net', 'tcp'),
                    'udp': True
                }
                if res['tls']:
                    res['server-name'] = d.get('sni', d.get('host', '')) or res['server']
                if res['network'] == 'ws' and d.get('host'):
                    res['ws-opts'] = {'headers': {'Host': d['host']}}
                return res
            except (json.JSONDecodeError, ValueError):
                return None

        elif s == 'trojan':
            password, rest2 = rest.split('@', 1)
            if '#' in rest2:
                hp_params, name_part = rest2.split('#', 1)
            else:
                hp_params, name_part = rest2, ''
            if '?' in hp_params:
                hp, query_str = hp_params.split('?', 1)
            else:
                hp, query_str = hp_params, ''
            if '/' in hp: hp = hp.split('/')[0]
            if ':' not in hp: return None
            h, p_str = hp.split(':', 1)
            p = safe_int(p_str)
            if not p: return None
            name = unquote(name_part) if name_part else f"Trojan-{h}"
            q = parse_qs(query_str) if query_str else {}
            res = {
                'name': name, 'type': 'trojan', 'server': h, 'port': p,
                'password': password, 'udp': True
            }
            sni = safe_str(q.get('sni'), '')
            host_header = safe_str(q.get('host'), '')
            if sni: res['sni'] = sni
            if safe_str(q.get('security'), '') in ['tls', 'xtls']:
                res['tls'] = True
                res['server-name'] = sni if sni else h
            if host_header: res['host'] = host_header
            return res

        elif s == 'ss':
            if '@' in rest:
                userinfo, hp_name = rest.split('@', 1)
                if '#' in hp_name:
                    hp, name_part = hp_name.split('#', 1)
                else:
                    hp, name_part = hp_name, ''
                if '/' in hp: hp = hp.split('/')[0]
                if ':' in hp:
                    h, p_str = hp.split(':', 1)
                    p = safe_int(p_str)
                    if not p: return None
                    if ':' in userinfo:
                        cipher, password = userinfo.split(':', 1)
                    else:
                        cipher = 'aes-256-gcm'
                        password = decode_base64(userinfo)
                    name = unquote(name_part) if name_part else f"SS-{h}"
                    return {
                        'name': name, 'type': 'ss', 'server': h, 'port': p,
                        'cipher': cipher, 'password': password, 'udp': True
                    }

        elif s in ['hysteria', 'hysteria2', 'hy2']:
            if '#' in rest:
                params_auth, name_part = rest.split('#', 1)
            else:
                params_auth, name_part = rest, ''
            if '?' in params_auth:
                auth, query_str = params_auth.split('?', 1)
            else:
                auth, query_str = params_auth, ''
            if '@' in auth:
                password, hp = auth.split('@', 1)
            else:
                password, hp = '', auth
            if '/' in hp: hp = hp.split('/')[0]
            if ':' in hp:
                h, p_str = hp.split(':', 1)
                p = safe_int(p_str)
                if not p: return None
                name = unquote(name_part) if name_part else f"Hysteria-{h}"
                q = parse_qs(query_str) if query_str else {}
                res = {
                    'name': name, 'type': 'hysteria2' if s == 'hy2' else s,
                    'server': h, 'port': p, 'password': password, 'udp': True
                }
                sni = safe_str(q.get('sni'), '')
                if sni:
                    res['sni'] = sni
                    res['server-name'] = sni
                return res

        elif s == 'tuic':
            if '@' in rest:
                userinfo, rest2 = rest.split('@', 1)
                if '#' in rest2:
                    hp_params, name_part = rest2.split('#', 1)
                else:
                    hp_params, name_part = rest2, ''
                if '?' in hp_params:
                    hp, query_str = hp_params.split('?', 1)
                else:
                    hp, query_str = hp_params, ''
                if '/' in hp: hp = hp.split('/')[0]
                if ':' in hp:
                    h, p_str = hp.split(':', 1)
                    p = safe_int(p_str)
                    if not p: return None
                    if ':' in userinfo:
                        uuid, password = userinfo.split(':', 1)
                    else:
                        uuid, password = userinfo, ''
                    name = unquote(name_part) if name_part else f"TUIC-{h}"
                    q = parse_qs(query_str) if query_str else {}
                    return {
                        'name': name, 'type': 'tuic', 'server': h, 'port': p,
                        'uuid': uuid, 'password': password,
                        'congestion-controller': safe_str(q.get('congestion_control'), 'bbr'),
                        'udp-relay-mode': safe_str(q.get('udp_relay_mode'), 'native'),
                        'udp': True, 'sni': safe_str(q.get('sni'), h)
                    }
    except Exception:
        pass
    return None

_GO_NUM_RE = re.compile(r'^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$')
_YAML_WORDS = {'y', 'n', 'yes', 'no', 'on', 'off', 'true', 'false', 'null', '~'}

class QuoteDumper(yaml.SafeDumper):
    pass

def _str_repr(dumper, data):
    if _GO_NUM_RE.match(data) or data.lower() in _YAML_WORDS:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

QuoteDumper.add_representer(str, _str_repr)

def write_yaml(filename, clash_proxies):
    names = [p['name'] for p in clash_proxies] if clash_proxies else ['DIRECT']
    clash_config = {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'Rule', 'log-level': 'info',
        'external-controller': '127.0.0.1:9090', 'proxies': clash_proxies,
        'proxy-groups': [
            {'name': '♻️ Auto', 'type': 'url-test', 'proxies': names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
            {'name': '🚀 Proxy', 'type': 'select', 'proxies': ['♻️ Auto'] + names}
        ],
        'rules': ['MATCH,🚀 Proxy']
    }
    with open(filename, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, Dumper=QuoteDumper, sort_keys=False, allow_unicode=True)

def write_txt(filename, uris, count_alive):
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    header = [f"# Обновлено: {ts}", f"# Живых: {count_alive}", "#"]
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("\n".join(header + uris))

async def main():
    start = time.time()
    if not os.path.exists(SOURCES_FILE):
        print("sources.txt не найден!"); return
    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    http_sem = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
    ping_sem = asyncio.Semaphore(MAX_CONCURRENT_PING)
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_DAYS)
    all_proxies, sub_urls, visited = [], set(), set()
    web_sources, telethon_sources = [], []
    for src in sources:
        if not src.startswith('http'): continue
        if src.startswith('https://t.me/'):
            if 'LowiKForum' in src or any(x in src.lower() for x in ['chat', 'forum']):
                telethon_sources.append(src)
            else:
                web_sources.append(src)
        else:
            sub_urls.add(clean_url(src))
    print(f"[{time.time()-start:.1f}s] Web: {len(web_sources)}, Telethon: {len(telethon_sources)}")
    if web_sources:
        async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
            tasks = []
            for src in web_sources:
                if re.search(r'/\d+$', src):
                    url = f"{src}?embed=1&mode=tme"
                else:
                    url = src.replace('https://t.me/', 'https://t.me/s/')
                tasks.append((url, fetch(session, url, http_sem)))
            results = await asyncio.gather(*[t[1] for t in tasks])
            for (u, _), html_content in zip(tasks, results):
                if html_content:
                    p, u2 = extract_messages_data(html_content, cutoff)
                    debug_log(f"Из {u[:60]}: {len(p)} прокси, {len(u2)} URL")
                    all_proxies.extend(p)
                    for l in u2: sub_urls.add(clean_url(l))
    if telethon_sources:
        if TELETHON_OK and SESSION_B64 and API_ID != 0:
            print(f"[{time.time()-start:.1f}s] Парсим через Telethon ({len(telethon_sources)} источников)...")
            for src in telethon_sources:
                p, u = await parse_with_telethon(src, cutoff)
                all_proxies.extend(p)
                for l in u: sub_urls.add(clean_url(l))
        else:
            debug_log(f"⚠️ Telethon не настроен, пропускаем {len(telethon_sources)} источников")
    if sub_urls:
        clean_subs = set()
        for url in sub_urls:
            u = url.rstrip('/')
            if u not in clean_subs:
                clean_subs.add(u)
        print(f"[{time.time()-start:.1f}s] Обрабатываем {len(clean_subs)} подписок...")
        async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
            tasks = [process_subscription(url, session, http_sem, visited) for url in clean_subs]
            results = await asyncio.gather(*tasks)
            for r in results: all_proxies.extend(r)
    all_proxies = [p for p in set(all_proxies) if p and '://' in p]
    print(f"[{time.time()-start:.1f}s] Сырых прокси: {len(all_proxies)}")

    # дедуп по конфигу ДО пинга (меньше пингов, детерминированный порядок)
    n0 = len(all_proxies)
    all_proxies = dedupe_by_config(all_proxies)
    debug_log(f"🔁 Дублей по конфигу удалено: {n0 - len(all_proxies)} (осталось {len(all_proxies)})")

    happ, ping_list = [], []
    for u in all_proxies:
        (happ if u.lower().startswith('happ://') else ping_list).append(u)
    print(f"[{time.time()-start:.1f}s] Пингуем {len(ping_list)} серверов...")
    alive = []
    tasks, pmap = [], {}
    parse_errors = 0
    for u in ping_list:
        parsed = parse_uri_for_clash(u)
        if parsed and parsed.get('server') and parsed.get('port'):
            tasks.append(check_proxy_tcp(parsed['server'], parsed['port'], ping_sem))
            pmap[len(tasks)-1] = (u, parsed)
        else:
            parse_errors += 1
    if parse_errors:
        debug_log(f"⚠️ Не удалось распарсить {parse_errors} прокси")
    if tasks:
        results = await asyncio.gather(*tasks)
        for i, ok in enumerate(results):
            if ok: alive.append(pmap[i])
    print(f"[{time.time()-start:.1f}s] Живых: {len(alive)}")
    type_stats = {}
    for _, p in alive:
        t = p.get('type', 'unknown')
        type_stats[t] = type_stats.get(t, 0) + 1
    debug_log(f"📊 Типы живых прокси: {type_stats}")

    alive_uris_all = [u for u, _ in alive]
    enabled_protocols = get_enabled_protocols()

    # PROXY-ALL
    clash_all = [sanitize_proxy(p) for _, p in alive]
    clash_all, _ = filter_by_protocol(clash_all)
    clash_all = validate_all(clash_all)
    clash_all = make_names_unique(clash_all)

    all_txt_uris = alive_uris_all + happ
    all_txt_uris = deduplicate_proxies(all_txt_uris)

    write_txt(OUT_ALL_TXT, all_txt_uris, len(alive))
    write_yaml(OUT_ALL_YAML, clash_all)
    debug_log(f"📄 proxy-all.txt: {len(all_txt_uris)} ссылок")
    debug_log(f"📄 proxy-all.yaml: {len(clash_all)} прокси")

    # PROXY (белосписочные)
    clash_wl = [sanitize_proxy(p) for _, p in alive]
    clash_wl, _ = filter_by_protocol(clash_wl)

    before_filter = len(clash_wl)
    clash_wl = [p for p in clash_wl if matches_roots(p)]
    debug_log(f"🎯 ФИЛЬТР по корням: было {before_filter}, стало {len(clash_wl)}")

    clash_wl = validate_all(clash_wl)
    clash_wl = make_names_unique(clash_wl)

    wl_uris = []
    for uri, parsed in alive:
        if parsed.get('type') not in enabled_protocols:
            continue
        if not matches_roots(parsed):
            continue
        wl_uris.append(uri)

    wl_uris = deduplicate_proxies(wl_uris)

    write_txt(OUT_TXT, wl_uris, len(wl_uris))
    write_yaml(OUT_YAML, clash_wl)
    debug_log(f"📄 proxy.txt: {len(wl_uris)} ссылок")
    debug_log(f"📄 proxy.yaml: {len(clash_wl)} прокси")

    final_types_all = {}
    for p in clash_all:
        t = p.get('type', 'unknown')
        final_types_all[t] = final_types_all.get(t, 0) + 1
    debug_log(f"📊 ИТОГО proxy-all.yaml: {len(clash_all)} прокси {final_types_all}")

    final_types_wl = {}
    for p in clash_wl:
        t = p.get('type', 'unknown')
        final_types_wl[t] = final_types_wl.get(t, 0) + 1
    debug_log(f"📊 ИТОГО proxy.yaml: {len(clash_wl)} прокси {final_types_wl}")

    print(f"✅ Готово за {time.time()-start:.1f} сек!")

if __name__ == '__main__':
    asyncio.run(main())
