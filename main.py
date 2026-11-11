import os
import re
import base64
import asyncio
import json
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlparse, urlsplit, urlencode, urlunsplit

import aiohttp
import yaml
from bs4 import BeautifulSoup

try:
    from telethon import TelegramClient
    from telethon.tl.types import MessageEntityTextUrl
    TELETHON_OK = True
except ImportError:
    TELETHON_OK = False

try:
    import lxml  # noqa: F401
    HTML_PARSER = 'lxml'
except ImportError:
    HTML_PARSER = 'html.parser'

SOURCES_FILE = 'sources.txt'
OUT_TXT = 'proxy.txt'
OUT_YAML = 'proxy.yaml'
OUT_ALL_TXT = 'proxy-all.txt'
OUT_ALL_YAML = 'proxy-all.yaml'
ISSUE_FILE = 'issue.txt'

MAX_DAYS_WL = 50
MAX_DAYS_ALL = 10
LIMIT_WL = 1000          # сообщений на канал через Telethon
TME_MAX_PAGES = 10       # страниц истории t.me/s/ на канал (~20 постов каждая)
TME_SUB_PAGES = 2        # страниц для каналов, найденных внутри подписок

TIMEOUT = aiohttp.ClientTimeout(total=12, connect=7)
TIMEOUT_LONG = aiohttp.ClientTimeout(total=30, connect=10)
PING_TIMEOUT = 2.0
MAX_CONCURRENT_HTTP = 50
MAX_CONCURRENT_PING = 500
MAX_PER_ENDPOINT = 5

API_ID = int(os.getenv('TELEGRAM_API_ID', '0'))
API_HASH = os.getenv('TELEGRAM_API_HASH', '')
SESSION_B64 = os.getenv('TELEGRAM_SESSION', '')

PROXY_SCHEMES = ['vless', 'vmess', 'ss', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'happ']
_SCHEMES_ALT = '|'.join(PROXY_SCHEMES)
# '#' и пробел исключены из тела: иначе regex съедал '#' и терял имя целиком
_URL_BODY = r'[a-zA-Z0-9\-._~:/?\[\]@!$&\'()*+,;=%{}]'
PROXY_REGEX = re.compile(r'(?:' + _SCHEMES_ALT + r')://' + _URL_BODY + r'+(?:#[^\s"<>]*)?', re.IGNORECASE)
URL_REGEX = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)

ISSUE_SCHEMES = ['csqtt', 'qwdtt', 'olcrtc', 'openflux']
_ISSUE_ALT = '|'.join(ISSUE_SCHEMES)
ISSUE_REGEX = re.compile(r'(?:' + _ISSUE_ALT + r')://' + _URL_BODY + r'+(?:#[^\s"<>]*)?', re.IGNORECASE)
ISSUE_URLS = set()

BLACKLIST_DOMAINS = [
    'youtube.com', 'youtu.be', 'instagram.com', 'twitter.com', 'x.com',
    'vk.com', 'ok.ru', 'pikabu.ru', 'habr.com', 'dzen.ru', 'mail.ru', 'rambler.ru', 'meduza.io', 'kommersant.ru', 'cnews.ru',
    'iz.ru', 'techradar.com', 'openai.com', 'sozd.duma.gov.ru',
    'playgta5.com', 'mrbeast.nocp.uz', 'cloud.mail.ru', 'max.ru',
    'ria.ru', 'lenta.ru', 'rbc.ru', 'vedomosti.ru', 'tass.ru'
]

# страницы, где ключей заведомо нет (магазины, донаты, статьи, промо)
JUNK_DOMAINS = [
    'play.google.com', 'apps.apple.com', 'testflight.apple.com',
    'donationalerts.com', 'pay.cloudtips.ru', 'finance.ozon.ru',
    'letmegooglethat.com', 'consumer.ftc.gov', 'cisa.gov',
    'telegram.org', 'telega.in', 'tgproxy.pink',
]

STICKY_WORDS = ['Gemini', 'Gemini:', 'Claude', 'ChatGPT']
WHITELIST_ROOTS = "бел спис обход авто глушил lte 4g 5g mobil white notorgames бс теле мтс касаад"

# В proxy.txt / proxy.yaml (WL) попадают ТОЛЬКО эти протоколы:
WL_PROTOCOLS = {'vless'}
# максимум embed-сообщений чужих каналов, докачиваемых из подписок (0 = без лимита)
MAX_EMBED_SUBS = 200

ENABLE_VLESS = True
ENABLE_VMESS = False
ENABLE_SS = False
ENABLE_TROJAN = False
ENABLE_HYSTERIA = False
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
_TOKEN_RE = re.compile(r'[^0-9a-zа-яё]+')

IGNORED_PARAMS = {'fp', 'alpn', 'extra', 'headertype', 'encryption', 'allowinsecure',
                  'insecure', 'fm', 'packetencoding', 'spx', 'ed'}
DEDUP_SCHEMES = {'vless', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic'}
DEDUP_IGNORE_USER = False

_AMP_RE = re.compile(r'&(?:amp|#0*38|#x0*26);', re.I)
PROBLEM_DOMAINS = ['kfwl.lol', 'pozor.bond', 'atlanta-subs.ru', 'astra-sub.com', 'taurus-sync.com', 'net4.su']

DEBUG = os.getenv('DEBUG', '1') == '1'

def debug_log(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}", flush=True)

def now_utc():
    return datetime.now(timezone.utc)

def decode_base64(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding:
        s += '=' * (4 - padding)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return ""

# ---------------------------------------------------------------- URL helpers

def is_valid_url(url):
    try:
        r = urlparse(url)
        if not all([r.scheme, r.netloc]):
            return False
        if r.scheme == 'tg':
            return False
        host = (r.hostname or '').lower()
        # точное совпадение домена/поддомена, а не подстроки
        # (старый вариант отсеивал netflix.com из-за 'x.com')
        for d in BLACKLIST_DOMAINS + JUNK_DOMAINS:
            if host == d or host.endswith('.' + d):
                return False
        path = r.path.lower()
        if host == 'github.com' and '/releases' in path:
            return False
        if path.endswith('.md'):
            return False
        if host == 'pozor.bond' and path.startswith('/status/'):
            return False
        return True
    except Exception:
        return False

def is_useless_tme(url):
    if not ('t.me' in url or 'telegram.me' in url):
        return False
    if '/proxy?' in url or '/webproxy?' in url:
        return True
    if '/joinchat/' in url:
        return True
    if '/+' in url.split('//', 1)[-1][:10]:
        return True
    path = urlparse(url).path.strip('/')
    if '/' not in path and path.lower().endswith('bot'):
        return True
    return False

def split_glued(url):
    base = 8 if url.startswith('https://') else 7
    rest = url[base:]
    for proto in ['https://', 'http://']:
        idx = rest.find(proto)
        if idx > 0 and rest[idx - 1] != '/':
            return url[:base + idx]
    if url.count('@') >= 2:
        at_idx = rest.index('@')
        part_before_at = rest[:at_idx]
        if '/' not in part_before_at and ':' not in part_before_at:
            return url[:base + at_idx]
    return url

def remove_sticky_words(url):
    for word in STICKY_WORDS:
        if url.endswith(word):
            url = url[:-len(word)]
    return url.rstrip('/')

_TRACK_KEYS = {'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
               'fbclid', 'gclid', 'yclid', 'ysclid', 'ref_type', 'erid'}

def normalize_sub_url(url):
    """Схлопывает дубли: трекинг-параметры и зеркала hub.mos.ru.
    Важные параметры (key, id, ref, token) не трогаются."""
    if 'hub.mos.ru/' in url:
        url = url.replace('/-/raw/', '/raw/')
    try:
        parts = urlsplit(url)
        if parts.query:
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            if any(k.lower() in _TRACK_KEYS for k, _ in pairs):
                kept = [(k, v) for k, v in pairs if k.lower() not in _TRACK_KEYS]
                url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                  urlencode(kept), parts.fragment))
    except Exception:
        pass
    return url

def clean_url(url):
    url = url.strip()
    while _AMP_RE.search(url):
        url = _AMP_RE.sub('&', url)
    head, sep, frag = url.partition('#')
    for i, c in enumerate(head):
        if ord(c) > 127:
            head, sep, frag = head[:i], '', ''
            break
    frag = quote(frag.strip(), safe="-._~:/?#[]@!$&'()*+,;=%")
    if not frag:
        sep = ''
    url = head + sep + frag
    while url.endswith(')') and url.count(')') > url.count('('):
        url = url[:-1]
    url = url.rstrip('.,;:!?')
    # склейки чиним только у http(s): иначе резались легитимные
    # vless://...path=...https://... (баг старой версии)
    if url.startswith(('http://', 'https://')):
        url = remove_sticky_words(split_glued(url))
        url = normalize_sub_url(url)
    return url

def is_valid_issue_url(url):
    if not url or '://' not in url or len(url) < 40:
        return False
    scheme, rest = url.split('://', 1)
    if not rest or rest.strip() in (',', ' ', '', '@'):
        return False
    if rest.startswith(('import', 'jitsi?datachannel@')):
        return False
    if scheme == 'qwdtt' and 'config?' in rest:
        if 'peer=' not in rest and 'pass=' not in rest:
            return False
    return True

def split_glued_issues(url):
    """Старый цикл терял все склеенные ссылки кроме первой."""
    pattern = re.compile(r'(?<!^)(?<!\s)(' + _ISSUE_ALT + r')://', re.I)
    parts = pattern.split(url)
    if len(parts) == 1:
        return [url]
    return [parts[i].lower() + '://' + parts[i + 1] for i in range(1, len(parts) - 1, 2)]

def collect_url(raw, urls):
    u = clean_url(raw)
    if not u:
        return
    if 't.me' in u or 'telegram.me' in u:
        if not is_useless_tme(u):
            urls.append(u)
    elif is_valid_url(u):
        urls.append(u)

# ---------------------------------------------------------------- dedup

def make_names_unique(proxies):
    used = {}
    renamed = 0
    for p in proxies:
        name = (p.get('name') or '').strip()
        if not name:
            name = f"{p.get('type', 'proxy')}-{p.get('server', 'unknown')}:{p.get('port', 0)}"
        if name in used:
            used[name] += 1
            name = f"{name} #{used[name]}"
            renamed += 1
        else:
            used[name] = 1
        p['name'] = name
    if renamed:
        debug_log(f"🏷️ Переименовано дубликатов имён: {renamed}")
    return proxies

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
        return uri
    scheme, user, pwd, host, port, path, q, _ = p
    q = {k: v for k, v in q.items() if v and k not in IGNORED_PARAMS}
    if q.get('type') == 'raw':
        q['type'] = 'tcp'
    q.setdefault('type', 'tcp')
    if q.get('mode') == 'auto':
        del q['mode']
    if q.get('security') == 'tls':
        eff = q.get('sni') or q.get('host')
        if eff:
            q['sni'] = eff
            if q.get('host') == eff:
                q.pop('host')
    if q['type'] == 'tcp':
        q.pop('path', None)
        q.pop('host', None)
    if DEDUP_IGNORE_USER and scheme == 'vless':
        user = ''
        if q.get('security') == 'reality':
            q.pop('sid', None)
    return (scheme, user, pwd, host, port, path, tuple(sorted(q.items())))

def matches_roots(p):
    """Совпадение по НАЧАЛУ слова, а не по подстроке.
    Старый вариант: 'lte' ловился внутри 'filter', 'бс' — внутри 'обслуж...',
    '4g'/'5g' — внутри hex-поддоменов -> в WL попадал мусор."""
    searchable = ' '.join([
        str(p.get('name', '')), str(p.get('server', '')),
        str(p.get('sni', '')), str(p.get('server-name', '')),
    ]).lower()
    tokens = [t for t in _TOKEN_RE.split(searchable) if t]
    return any(t.startswith(root) for t in tokens for root in _KEYWORD_ROOTS)

def _rank(uri):
    p = _uri_parts(uri)
    if not p:
        return (False, 0)
    return (matches_roots({'name': p[7], 'server': p[3], 'sni': p[6].get('sni', '')}), len(p[7]))

def dedupe_by_config(uris):
    groups = {}
    for u in sorted(set(uris)):
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

# ---------------------------------------------------------------- validate

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

def sanitize_proxy(p):
    net = p.get('network')
    if net not in VALID_NETWORKS:
        p['network'] = 'tcp'
        net = 'tcp'
    for opt_net, opt_key in (('ws', 'ws-opts'), ('grpc', 'grpc-opts'), ('h2', 'h2-opts'),
                             ('http', 'http-opts'), ('xhttp', 'xhttp-opts'),
                             ('httpupgrade', 'http-upgrade-opts')):
        if net != opt_net and opt_key in p:
            del p[opt_key]
    if isinstance(p.get('ws-opts'), dict):
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
        sn = p.get('server-name') or p.get('servername') or p.get('sni')
        if not sn:
            sn = p.get('server', '')
        p['server-name'] = sn
        p.pop('servername', None)
    uuid = p.get('uuid', '')
    if isinstance(uuid, str):
        p['uuid'] = re.sub(r'[^0-9a-fA-F-]', '', uuid)
    return p

def validate_proxy(p):
    if not isinstance(p, dict):
        return False, 'not dict'
    ptype, server, port, name = p.get('type'), p.get('server'), p.get('port'), p.get('name')
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
        if not UUID_RE.match(p.get('uuid', '') or ''):
            return False, 'bad uuid format'
        if p.get('network') not in VALID_NETWORKS:
            return False, 'bad network'
        if ptype == 'vmess':
            if not isinstance(p.get('alterId'), int) or p.get('alterId') < 0:
                return False, 'bad alterId'
            if p.get('cipher') not in ('auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero'):
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
            return False, 'bad cipher'
    elif ptype == 'hysteria':
        if not (p.get('auth-str') or p.get('password')):
            return False, 'empty auth'
    elif ptype == 'hysteria2':
        if not p.get('password'):
            return False, 'empty password'
    elif ptype == 'tuic':
        if not UUID_RE.match(p.get('uuid', '') or ''):
            return False, 'bad uuid'
    else:
        return False, 'unknown type'
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

# ---------------------------------------------------------------- URI parser

def _split_hostport(hp):
    """host:port с поддержкой IPv6 [::1]:443."""
    hp = hp.split('/', 1)[0].strip()
    if hp.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)$', hp)
        if not m:
            return None
        host, port = m.group(1), int(m.group(2))
    else:
        if ':' not in hp:
            return None
        host, p_str = hp.rsplit(':', 1)
        if not host or not p_str.isdigit():
            return None
        port = int(p_str)
    return (host, port) if 1 <= port <= 65535 else None

def _truthy(v):
    return str(v).lower() in ('1', 'true', 'yes')

def _transport(res, q):
    """Общие ws/grpc/httpupgrade/xhttp опции для vless/trojan."""
    nt = res.get('network', 'tcp')
    path = unquote(q.get('path', [''])[0])
    host = q.get('host', [''])[0]
    if nt == 'ws':
        ws = {'path': path if path.startswith('/') else '/' + (path or '')}
        if host:
            ws['headers'] = {'Host': host}
        ed = q.get('ed', [''])[0]
        if ed.isdigit() and int(ed) > 0:
            ws['max-early-data'] = int(ed)
            ws['early-data-header-name'] = 'Sec-WebSocket-Protocol'
        res['ws-opts'] = ws
    elif nt == 'grpc':
        service = q.get('serviceName', [''])[0]
        if service:
            res['grpc-opts'] = {'grpc-service-name': service}
        if q.get('mode', [''])[0] == 'multi':
            res.setdefault('grpc-opts', {})['grpc-mode'] = 'multi'
    elif nt == 'httpupgrade':
        opts = {'path': path if path.startswith('/') else '/' + (path or '')}
        if host:
            opts['headers'] = {'Host': host}
        res['http-upgrade-opts'] = opts
    elif nt == 'xhttp':
        opts = {}
        if path:
            opts['path'] = path
        if host:
            opts['host'] = host
        if opts:
            res['xhttp-opts'] = opts

def parse_uri_for_clash(uri):
    def s1(q, key, default=''):
        v = q.get(key)
        return v[0] if v and v[0] else default
    try:
        scheme, rest = uri.split('://', 1)
        scheme = scheme.lower()
        if scheme == 'happ':
            return None

        if scheme in ('vless', 'trojan'):
            userinfo, rest2 = rest.split('@', 1)
            hp_params, _, name_part = rest2.partition('#')
            hp, _, query_str = hp_params.partition('?')
            parsed_hp = _split_hostport(hp)
            if not parsed_hp:
                return None
            h, p = parsed_hp
            q = parse_qs(query_str)
            name = unquote(name_part).strip() or f"{scheme.upper()}-{h}"
            if scheme == 'vless':
                nt = s1(q, 'type', 'tcp')
                if nt == 'raw':
                    nt = 'tcp'
                res = {'name': name, 'type': 'vless', 'server': h, 'port': p,
                       'uuid': unquote(userinfo), 'network': nt, 'udp': True}
            else:
                nt = s1(q, 'type', 'tcp')
                res = {'name': name, 'type': 'trojan', 'server': h, 'port': p,
                       'password': unquote(userinfo), 'network': nt, 'udp': True, 'tls': True}
            security = s1(q, 'security', 'tls' if scheme == 'trojan' else '')
            sni = s1(q, 'sni') or s1(q, 'peer')
            fp = s1(q, 'fp')
            if security == 'reality':
                pbk = s1(q, 'pbk')
                sid = s1(q, 'sid').strip()
                if not pbk:
                    return None
                res['tls'] = True
                res['server-name'] = sni or h
                ro = {'public-key': pbk}
                if sid:
                    if not SID_RE.match(sid):
                        return None
                    ro['short-id'] = sid
                res['reality-opts'] = ro
                if fp:
                    res['client-fingerprint'] = fp
                flow = s1(q, 'flow')
                if flow:
                    res['flow'] = flow
            elif security in ('tls', 'xtls'):
                res['tls'] = True
                res['server-name'] = sni or h
                if fp:
                    res['client-fingerprint'] = fp
            if _truthy(s1(q, 'insecure')) or _truthy(s1(q, 'allowInsecure')):
                res['skip-cert-verify'] = True
            alpn = s1(q, 'alpn')
            if alpn:
                res['alpn'] = alpn.split(',')
            _transport(res, q)
            return res

        if scheme == 'vmess':
            d = json.loads(decode_base64(rest.split('#', 1)[0]))
            if not isinstance(d, dict):
                return None
            try:
                port = int(str(d.get('port', 0)))
            except ValueError:
                return None
            net = d.get('net', 'tcp')
            if net == 'raw':
                net = 'tcp'
            cipher = d.get('scy') or 'auto'
            if cipher not in ('auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero'):
                cipher = 'auto'
            res = {'name': d.get('ps') or f"VM-{d.get('add', 'unknown')}",
                   'type': 'vmess', 'server': d.get('add'), 'port': port,
                   'uuid': d.get('id', ''), 'alterId': int(str(d.get('aid', 0) or 0)),
                   'cipher': cipher, 'tls': d.get('tls') == 'tls',
                   'network': net, 'udp': True}
            if res['tls']:
                res['server-name'] = d.get('sni') or d.get('host') or res['server']
            path = d.get('path') or ''
            host = d.get('host') or ''
            if net == 'ws':
                ws = {}
                if path:
                    ws['path'] = path if path.startswith('/') else '/' + path
                if host:
                    ws['headers'] = {'Host': host}
                if ws:
                    res['ws-opts'] = ws
            elif net in ('h2', 'http') and path:
                res[f'{net}-opts'] = {'path': [path]}
            elif net == 'grpc' and path:
                res['grpc-opts'] = {'grpc-service-name': path}
            return res

        if scheme == 'ss':
            body, _, name_part = rest.partition('#')
            name = unquote(name_part).strip()
            if '@' in body:
                # SIP002: ss://[base64(method:password) | method:password]@host:port
                userinfo, hp = body.rsplit('@', 1)
                userinfo = unquote(userinfo)
                if ':' in userinfo:
                    cipher, password = userinfo.split(':', 1)
                else:
                    decoded = decode_base64(userinfo)
                    if ':' in decoded:
                        cipher, password = decoded.split(':', 1)
                    else:
                        return None
            else:
                # legacy: ss://base64(method:password@host:port)
                decoded = decode_base64(body)
                if '@' not in decoded or ':' not in decoded:
                    return None
                userinfo, hp = decoded.rsplit('@', 1)
                if ':' not in userinfo:
                    return None
                cipher, password = userinfo.split(':', 1)
            parsed_hp = _split_hostport(hp)
            if not parsed_hp or not password:
                return None
            h, p = parsed_hp
            if cipher == 'chacha20-poly1305':
                cipher = 'chacha20-ietf-poly1305'
            return {'name': name or f"SS-{h}", 'type': 'ss', 'server': h, 'port': p,
                    'cipher': cipher, 'password': password, 'udp': True}

        if scheme in ('hysteria', 'hysteria2', 'hy2'):
            params_auth, _, name_part = rest.partition('#')
            auth, _, query_str = params_auth.partition('?')
            if '@' in auth:
                password, hp = auth.rsplit('@', 1)
            else:
                password, hp = '', auth
            parsed_hp = _split_hostport(hp)
            if not parsed_hp:
                return None
            h, p = parsed_hp
            q = parse_qs(query_str)
            ptype = 'hysteria2' if scheme in ('hysteria2', 'hy2') else 'hysteria'
            res = {'name': unquote(name_part).strip() or f"HY-{h}", 'type': ptype,
                   'server': h, 'port': p, 'udp': True}
            password = unquote(password)
            if ptype == 'hysteria2':
                res['password'] = password
            else:
                res['auth-str'] = password
            sni = s1(q, 'sni')
            if sni:
                res['sni'] = sni
            if _truthy(s1(q, 'insecure')) or _truthy(s1(q, 'allowInsecure')):
                res['skip-cert-verify'] = True
            obfs = s1(q, 'obfs')
            if obfs and obfs != 'none':
                res['obfs'] = obfs
                res['obfs-password'] = s1(q, 'obfs-password')
            alpn = s1(q, 'alpn')
            if alpn:
                res['alpn'] = alpn.split(',')
            return res

        if scheme == 'tuic':
            userinfo, rest2 = rest.split('@', 1)
            hp_params, _, name_part = rest2.partition('#')
            hp, _, query_str = hp_params.partition('?')
            parsed_hp = _split_hostport(hp)
            if not parsed_hp:
                return None
            h, p = parsed_hp
            userinfo = unquote(userinfo)
            uuid, _, password = userinfo.partition(':')
            q = parse_qs(query_str)
            res = {'name': unquote(name_part).strip() or f"TUIC-{h}", 'type': 'tuic',
                   'server': h, 'port': p, 'uuid': uuid, 'password': password,
                   'congestion-controller': s1(q, 'congestion_control', 'bbr'),
                   'udp-relay-mode': s1(q, 'udp_relay_mode', 'native'),
                   'udp': True, 'sni': s1(q, 'sni', h)}
            if _truthy(s1(q, 'allow_insecure')) or _truthy(s1(q, 'insecure')):
                res['skip-cert-verify'] = True
            alpn = s1(q, 'alpn')
            if alpn:
                res['alpn'] = alpn.split(',')
            return res
    except Exception:
        pass
    return None

# ---------------------------------------------------------------- extraction

def extract_from_element(element):
    proxies, urls = [], []
    if hasattr(element, 'find_all'):
        for a in element.find_all('a', href=True):
            href = a['href'].strip()
            if any(href.lower().startswith(f"{s}://") for s in PROXY_SCHEMES):
                proxies.append(clean_url(href))
            elif any(href.lower().startswith(f"{s}://") for s in ISSUE_SCHEMES):
                ISSUE_URLS.add(clean_url(href))
            elif href.startswith('http'):
                collect_url(href, urls)
    text = element.get_text() if hasattr(element, 'get_text') else str(element)
    proxies.extend(clean_url(m.group(0)) for m in PROXY_REGEX.finditer(text))
    for m in ISSUE_REGEX.finditer(text):
        ISSUE_URLS.add(clean_url(m.group(0)))
    for m in URL_REGEX.finditer(text):
        collect_url(m.group(0), urls)
    return list(set(proxies)), list(set(urls))

def extract_messages_data(html_content, cutoff_date):
    """Возвращает (прокси с РЕАЛЬНЫМИ датами, url, min_id для пагинации)."""
    soup = BeautifulSoup(html_content, HTML_PARSER)
    messages = soup.find_all('div', class_='tgme_widget_message')
    proxies, urls, min_id = [], [], None
    for msg in messages:
        post = msg.get('data-post', '')
        mid = post.rsplit('/', 1)[-1]
        if mid.isdigit():
            mid = int(mid)
            min_id = mid if min_id is None else min(min_id, mid)
        dt = now_utc()
        time_tag = msg.find('time')
        if time_tag and time_tag.get('datetime'):
            try:
                dt = datetime.fromisoformat(time_tag['datetime'].replace('Z', '+00:00'))
            except ValueError:
                pass
        if dt < cutoff_date:
            continue
        px, ur = extract_from_element(msg)
        proxies.extend((p, dt) for p in px)
        urls.extend(ur)
    return proxies, urls, min_id

# ---------------------------------------------------------------- network

def _headers_for(url):
    if 't.me/' in url or 'telegram.me/' in url:
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8',
        }
    return {
        'User-Agent': 'Happ/1.0 (com.happ; build:100; iOS 17.0.0) Alamofire/5.8.0',
        'Accept': '*/*',
        'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8',
    }

async def fetch(session, url, sem, retry_count=2):
    if not url.startswith(('http://', 'https://')):
        return ""
    headers = _headers_for(url)
    if 'kfwl.lol' in url:
        headers['Referer'] = 'https://t.me/'
    timeout = TIMEOUT_LONG if any(d in url for d in PROBLEM_DOMAINS) else TIMEOUT
    for attempt in range(retry_count + 1):
        retryable = False
        try:
            async with sem:  # семафор держим только на запрос, не на сон между ретраями
                async with session.get(url, headers=headers, allow_redirects=True, timeout=timeout) as resp:
                    if resp.status == 200:
                        text = (await resp.read()).decode('utf-8', errors='ignore')
                        debug_log(f"✓ {url[:80]}: {len(text)} симв.")
                        return text
                    retryable = resp.status in (403, 429, 500, 502, 503, 504)
        except asyncio.CancelledError:
            raise
        except Exception:
            retryable = True
        if not retryable or attempt == retry_count:
            return ""
        await asyncio.sleep(2 * (attempt + 1))
    return ""

async def fetch_tme_channel(session, sem, channel_url, cutoff, max_pages):
    """История канала через t.me/s/ с пагинацией ?before= (раньше — только 1 страница)."""
    proxies, urls, before = [], [], None
    for _ in range(max_pages):
        page_url = channel_url + (f'?before={before}' if before else '')
        html_text = await fetch(session, page_url, sem)
        if not html_text:
            break
        p, u, min_id = extract_messages_data(html_text, cutoff)
        proxies.extend(p)
        urls.extend(u)
        if not min_id or (before is not None and min_id >= before):
            break
        before = min_id
    return proxies, urls

async def parse_telethon_sources(sources, cutoff, limit):
    """Один клиент на все источники; для форумов читается конкретная тема."""
    if not SESSION_B64 or not TELETHON_OK or API_ID == 0:
        debug_log("Telethon не настроен")
        return [], []
    session_file = 'tg_session'
    try:
        with open(session_file + '.session', 'wb') as f:
            f.write(base64.b64decode(SESSION_B64))
    except Exception:
        return [], []
    proxies, urls = [], []
    client = TelegramClient(session_file, API_ID, API_HASH)
    try:
        await client.connect()
        if not await client.is_user_authorized():
            return [], []
        for source_url in sources:
            match = re.match(r'https?://t\.me/(?:c/)?([a-zA-Z0-9_]+)(?:/(\d+))?', source_url)
            if not match:
                continue
            chat_id = match.group(1)
            topic_id = int(match.group(2)) if match.group(2) else None
            if '/c/' in source_url:
                try:
                    chat_id = int(f"-100{chat_id}")
                except ValueError:
                    pass
            try:
                entity = await client.get_entity(chat_id)
            except Exception as e:
                debug_log(f"Telethon: не получить entity {chat_id}: {e}")
                continue
            kwargs = {'reply_to': topic_id} if topic_id and getattr(entity, 'forum', False) else {}
            try:
                async for msg in client.iter_messages(entity, limit=limit, **kwargs):
                    if not msg.date:
                        continue
                    dt = msg.date if msg.date.tzinfo else msg.date.replace(tzinfo=timezone.utc)
                    if dt < cutoff:
                        break
                    text = msg.text or msg.message or ''
                    for m in PROXY_REGEX.finditer(text):
                        proxies.append((clean_url(m.group(0)), dt))
                    for m in ISSUE_REGEX.finditer(text):
                        ISSUE_URLS.add(clean_url(m.group(0)))
                    for m in URL_REGEX.finditer(text):
                        collect_url(m.group(0), urls)
                    for ent in (msg.entities or []):
                        if isinstance(ent, MessageEntityTextUrl) and ent.url:
                            u = clean_url(ent.url)
                            if any(u.lower().startswith(f"{s}://") for s in PROXY_SCHEMES):
                                proxies.append((u, dt))
                            elif any(u.lower().startswith(f"{s}://") for s in ISSUE_SCHEMES):
                                ISSUE_URLS.add(u)
                            else:
                                collect_url(ent.url, urls)
            except Exception as e:
                debug_log(f"Telethon: ошибка чтения {chat_id}: {e}")
    except Exception as e:
        debug_log(f"Telethon: {e}")
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
        try:
            os.remove(session_file + '.session')
        except OSError:
            pass
    return proxies, urls

def _extract_from_sub_text(text):
    decoded = decode_base64(text)
    search_text = decoded if decoded and len(decoded) > 50 else text
    found = [clean_url(p) for p in PROXY_REGEX.findall(search_text)]
    for m in ISSUE_REGEX.finditer(search_text):
        ISSUE_URLS.add(clean_url(m.group(0)))
    return found

_TME_RE = re.compile(r'https?://(?:t\.me|telegram\.me)/(?:s/)?([a-zA-Z0-9_]+)(?:/(\d+))?')

def _sub_key(url):
    """Единый ключ для t.me-ссылок: /s/, регистр и хвосты не важны."""
    mm = _TME_RE.match(url)
    if mm:
        chan, msg_id = mm.group(1).lower(), mm.group(2)
        return f'tg:{chan}/{msg_id}' if msg_id else f'tg:{chan}'
    return url.rstrip('/')

async def process_subscription(url, session, sem, visited, cutoff):
    """Каналы t.me внутри подписок тоже парсим как /s/."""
    key = _sub_key(url)
    if key in visited:
        return []
    visited.add(key)
    if url.startswith('happ://'):
        return [(url, now_utc())]
    if not url.startswith(('http://', 'https://')) or is_useless_tme(url):
        return []
    if 't.me/' in url or 'telegram.me/' in url:
        mm = _TME_RE.match(url)
        if not mm:
            return []
        chan, msg_id = mm.group(1), mm.group(2)
        if msg_id:
            html_text = await fetch(session, f'https://t.me/{chan}/{msg_id}?embed=1&mode=tme', sem)
            if not html_text:
                return []
            p, _, _ = extract_messages_data(html_text, cutoff)
            return p
        p, _ = await fetch_tme_channel(session, sem, f'https://t.me/s/{chan}', cutoff, TME_SUB_PAGES)
        return p
    text = await fetch(session, url, sem)
    if not text:
        return []
    found = _extract_from_sub_text(text)
    if found:
        debug_log(f"✓ {len(found)} прокси в {url[:60]}")
    now = now_utc()
    return [(u, now) for u in found]

async def ping_endpoints(endpoints, sem):
    """Каждый уникальный (host, port) пингуется один раз. {endpoint: rtt|None}."""
    async def one(hp):
        async with sem:
            t0 = time.perf_counter()
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(hp[0], hp[1]), timeout=PING_TIMEOUT)
                rtt = time.perf_counter() - t0
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                return hp, rtt
            except asyncio.CancelledError:
                raise
            except Exception:
                return hp, None
    results = await asyncio.gather(*(one(hp) for hp in endpoints))
    return dict(results)

# ---------------------------------------------------------------- output

_GO_NUM_RE = re.compile(r'^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$')
_YAML_WORDS = {'y', 'n', 'yes', 'no', 'on', 'off', 'true', 'false', 'null', '~'}

class QuoteDumper(yaml.SafeDumper):
    pass

def _str_repr(dumper, data):
    if _GO_NUM_RE.match(data) or data.lower() in _YAML_WORDS:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

QuoteDumper.add_representer(str, _str_repr)

def _read_old_body(filename):
    """Тело файла без шапки-комментариев."""
    if not os.path.exists(filename):
        return None
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.read().splitlines()
    while lines and lines[0].startswith('#'):
        lines.pop(0)
    return '\n'.join(lines)

def _write_if_changed(filename, body, header_lines=()):
    """Запись только при изменении тела -> нет пустых ежечасных коммитов."""
    if _read_old_body(filename) == body:
        debug_log(f"📄 {filename}: без изменений, пропуск записи")
        return False
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(list(header_lines) + [body]) + '\n')
    return True

def write_yaml(filename, clash_proxies):
    names = [p['name'] for p in clash_proxies] if clash_proxies else ['DIRECT']
    clash_config = {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'Rule', 'log-level': 'info',
        'external-controller': '127.0.0.1:9090', 'proxies': clash_proxies,
        'proxy-groups': [
            {'name': '♻️ Auto', 'type': 'url-test', 'proxies': names,
             'url': 'http://www.gstatic.com/generate_204', 'interval': 300, 'tolerance': 50},
            {'name': '🚀 Proxy', 'type': 'select', 'proxies': ['♻️ Auto'] + names}
        ],
        'rules': ['MATCH,🚀 Proxy']
    }
    body = yaml.dump(clash_config, Dumper=QuoteDumper, sort_keys=False, allow_unicode=True).rstrip('\n')
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            if f.read().rstrip('\n') == body:
                debug_log(f"📄 {filename}: без изменений, пропуск записи")
                return False
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(body + '\n')
    return True

def write_txt(filename, uris, count_alive):
    ts = now_utc().strftime('%Y-%m-%d %H:%M:%S UTC')
    header = [f"# Обновлено: {ts}", f"# Живых: {count_alive}", "#"]
    return _write_if_changed(filename, '\n'.join(uris), header)

def write_issue_file():
    if not ISSUE_URLS:
        debug_log(f"📄 {ISSUE_FILE}: нет ссылок")
        return
    clean_urls = set()
    for url in ISSUE_URLS:
        for split_url in split_glued_issues(url):
            cleaned = clean_url(split_url)
            if is_valid_issue_url(cleaned):
                clean_urls.add(cleaned)
    if not clean_urls:
        debug_log(f"📄 {ISSUE_FILE}: нет валидных ссылок")
        return
    sorted_urls = sorted(clean_urls)
    ts = now_utc().strftime('%Y-%m-%d %H:%M:%S UTC')
    header = [f"# Обновлено: {ts}", f"# Найдено: {len(sorted_urls)}", "#"]
    _write_if_changed(ISSUE_FILE, '\n'.join(sorted_urls), header)
    debug_log(f"📄 {ISSUE_FILE}: {len(sorted_urls)} валидных (из {len(ISSUE_URLS)} сырых)")

# ---------------------------------------------------------------- pipeline

async def build_list(items, cutoff, label, ping_sem, ping_cache, whitelist=False):
    """Общий конвейер ALL и WL; пинг-кэш общий -> каждый endpoint проверяется 1 раз."""
    uris = dedupe_by_config([u for u, dt in items if dt >= cutoff])
    happ, parsed = [], {}
    parse_errors = 0
    for u in uris:
        if u.lower().startswith('happ://'):
            happ.append(u)
            continue
        p = parse_uri_for_clash(u)
        if p and p.get('server') and p.get('port'):
            parsed[u] = p
        else:
            parse_errors += 1
    if parse_errors:
        debug_log(f"⚠️ {label}: не распарсено {parse_errors}")
    endpoints = {(p['server'], p['port']) for p in parsed.values()}
    missing = endpoints - ping_cache.keys()
    print(f"[{label}] endpoint'ов: {len(endpoints)}, новых для пинга: {len(missing)}", flush=True)
    if missing:
        ping_cache.update(await ping_endpoints(missing, ping_sem))
    alive = [(u, p) for u, p in parsed.items() if ping_cache.get((p['server'], p['port'])) is not None]
    # детерминированный порядок -> минимальные diff'ы между запусками
    alive.sort(key=lambda up: (up[1]['type'], up[1]['server'], up[1]['port'], up[0]))
    print(f"[{label}] живых: {len(alive)}", flush=True)
    enabled = get_enabled_protocols()
    clash, txt_uris = [], []
    for u, p in alive:
        p = sanitize_proxy(dict(p))
        if whitelist:
            # WL: только протоколы из WL_PROTOCOLS и только с ключевыми словами
            if p.get('type') not in WL_PROTOCOLS or not matches_roots(p):
                continue
        elif p.get('type') not in enabled:
            txt_uris.append(u)  # в ALL.txt кладём все протоколы, как раньше
            continue
        ok, _ = validate_proxy(p)
        if ok:
            clash.append(p)
            txt_uris.append(u)
        elif not whitelist:
            txt_uris.append(u)
    clash = make_names_unique(clash)
    txt_uris = sorted(set(txt_uris + (happ if not whitelist else [])))
    types = {}
    for p in clash:
        types[p['type']] = types.get(p['type'], 0) + 1
    debug_log(f"📊 {label}: yaml={len(clash)} {types}, txt={len(txt_uris)}")
    return txt_uris, clash

async def main():
    start = time.time()
    if not os.path.exists(SOURCES_FILE):
        print("sources.txt не найден!")
        return
    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    http_sem = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
    ping_sem = asyncio.Semaphore(MAX_CONCURRENT_PING)
    cutoff_all = now_utc() - timedelta(days=MAX_DAYS_ALL)
    cutoff_wl = now_utc() - timedelta(days=MAX_DAYS_WL)
    items = []            # (uri, реальная дата сообщения)
    sub_urls = set()
    visited = set()
    web_channels, embed_msgs, telethon_sources = [], [], []
    for src in sources:
        if not src.startswith('http'):
            continue
        if re.match(r'https?://(t\.me|telegram\.me)/', src):
            if 'LowiKForum' in src or any(x in src.lower() for x in ('chat', 'forum')):
                telethon_sources.append(src)
            elif re.search(r'/\d+$', src):
                embed_msgs.append(src + '?embed=1&mode=tme')
            else:
                chan = re.sub(r'^https?://(t\.me|telegram\.me)/(s/)?', '', src).strip('/')
                web_channels.append(f'https://t.me/s/{chan}')
        else:
            sub_urls.add(clean_url(src))
    print(f"Каналов web: {len(web_channels)}, сообщений: {len(embed_msgs)}, "
          f"Telethon: {len(telethon_sources)}, подписок: {len(sub_urls)}", flush=True)
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_HTTP, ttl_dns_cache=300, ssl=False)
    async with aiohttp.ClientSession(connector=connector, timeout=TIMEOUT) as session:
        if web_channels or embed_msgs:
            tasks = [fetch_tme_channel(session, http_sem, u, cutoff_wl, TME_MAX_PAGES) for u in web_channels]
            tasks += [fetch(session, u, http_sem) for u in embed_msgs]
            results = await asyncio.gather(*tasks)
            for r in results:
                if isinstance(r, tuple):
                    p, u2 = r
                else:
                    p, u2, _ = extract_messages_data(r, cutoff_wl) if r else ([], [], None)
                items.extend(p)
                sub_urls.update(clean_url(u) for u in u2)
            for wc in web_channels:
                visited.add(_sub_key(wc))
        if telethon_sources:
            p, u = await parse_telethon_sources(telethon_sources, cutoff_wl, LIMIT_WL)
            items.extend(p)
            sub_urls.update(clean_url(x) for x in u)
        # ссылки на каналы, которые уже читаем напрямую, не нужны
        # (permalink'и постов ведут на те же сообщения -> сотни лишних запросов)
        known_chans = set()
        for src in web_channels + embed_msgs + telethon_sources:
            mm = _TME_RE.match(src)
            if mm:
                known_chans.add(mm.group(1).lower())
        if known_chans:
            n0 = len(sub_urls)
            sub_urls = {u for u in sub_urls
                        if not ((mm := _TME_RE.match(u)) and mm.group(1).lower() in known_chans)}
            debug_log(f"⏭️ Пропущено ссылок на уже прочитанные каналы: {n0 - len(sub_urls)}")
        if sub_urls:
            subs = sorted({u.rstrip('/') for u in sub_urls if u})
            if MAX_EMBED_SUBS > 0:
                embeds = [u for u in subs if (mm := _TME_RE.match(u)) and mm.group(2)]
                if len(embeds) > MAX_EMBED_SUBS:
                    drop = set(embeds[MAX_EMBED_SUBS:])
                    subs = [u for u in subs if u not in drop]
                    debug_log(f"⏭️ Embed-лимит: пропущено {len(drop)} чужих сообщений")
            print(f"[{time.time()-start:.1f}s] Подписок: {len(subs)}", flush=True)
            results = await asyncio.gather(*(process_subscription(u, session, http_sem, visited, cutoff_wl) for u in subs))
            for r in results:
                items.extend(r)
    # дедуп по URI с сохранением самой свежей даты
    seen = {}
    for uri, dt in items:
        if uri not in seen or dt > seen[uri]:
            seen[uri] = dt
    items = list(seen.items())
    print(f"[{time.time()-start:.1f}s] Сырых прокси: {len(items)}", flush=True)
    ping_cache = {}
    txt_all, clash_all = await build_list(items, cutoff_all, 'ALL', ping_sem, ping_cache)
    txt_wl, clash_wl = await build_list(items, cutoff_wl, 'WL', ping_sem, ping_cache, whitelist=True)
    write_txt(OUT_ALL_TXT, txt_all, len(txt_all))
    write_yaml(OUT_ALL_YAML, clash_all)
    write_txt(OUT_TXT, txt_wl, len(txt_wl))
    write_yaml(OUT_YAML, clash_wl)
    write_issue_file()
    print(f"✅ Готово за {time.time()-start:.1f} сек! (пингов всего: {len(ping_cache)})", flush=True)

if __name__ == '__main__':
    asyncio.run(main())
