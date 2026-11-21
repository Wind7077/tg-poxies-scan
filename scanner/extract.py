import base64
import html as html_mod
import json
import re
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlsplit, urlunsplit

import yaml
from bs4 import BeautifulSoup

from . import log

try:
    import lxml  # noqa: F401
    HTML_PARSER = 'lxml'
except ImportError:
    HTML_PARSER = 'html.parser'

PROXY_SCHEMES = ['vless', 'vmess', 'ss', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'happ']
SCHEMES_ALT = '|'.join(PROXY_SCHEMES)
ISSUE_SCHEMES = ['csqtt', 'qwdtt', 'olcrtc', 'openflux']
ISSUE_ALT = '|'.join(ISSUE_SCHEMES)

# '#' и пробел исключены из тела: иначе regex съедал '#' и терял имя целиком
_URL_BODY = r'[a-zA-Z0-9\-._~:/?\[\]@!$&\'()*+,;=%{}]'
PROXY_RE = re.compile(r'(?:' + SCHEMES_ALT + r')://' + _URL_BODY + r'+(?:#[^\s"<>]*)?', re.I)
URL_RE = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.I)
ISSUE_RE = re.compile(r'(?:' + ISSUE_ALT + r')://' + _URL_BODY + r'+(?:#[^\s"<>]*)?', re.I)

_HTML_HINT = re.compile(r'<\s*(?:!doctype|html|body|div|script|textarea)', re.I)
_URI_IN_HTML = re.compile(r'(?:' + SCHEMES_ALT + r')://[^\s"\'<>\\]+', re.I)
_B64_BLOB = re.compile(r'[A-Za-z0-9+/=_-]{200,}')
_B64_FULL = re.compile(r'^[A-Za-z0-9+/=_-]+$')

ISSUE_URLS = set()

_AMP_RE = re.compile(r'&(?:amp|#0*38|#x0*26);', re.I)
_TRACK_KEYS = {'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
               'fbclid', 'gclid', 'yclid', 'ysclid', 'ref_type', 'erid'}
# Антикэш-параметры: один и тот же файл приходил как ?ts=1792368845,
# ?ts=1792459069, ... — 6 копий одного источника. Срезаем ТОЛЬКО если
# значение числовое, чтобы не сломать подписки, где ts — часть токена.
_CACHE_KEYS = {'ts', '_', 'cb', 'nocache', 'rand', 'timestamp', 'cachebuster'}
_STICKY = ['Gemini', 'Gemini:', 'Claude', 'ChatGPT']
TME_RE = re.compile(r'https?://(?:t\.me|telegram\.me)/(?:s/)?([a-zA-Z0-9_]+)(?:/(\d+))?')

# Обёртки-прокси: без подсказки клиента отдают HTML вместо подписки
_KFWL_RE = re.compile(r'^(https?://p\.kfwl\.lol/)(.*)$', re.I)
_KFWL_HINT = 'ua=happ/os=android/'

_BARE_TLDS = {'co.uk', 'org.uk', 'com', 'net', 'org', 'ru', 'su', 'io', 'dev', 'me',
              'top', 'xyz', 'lol', 'gay', 'win', 'cc', 'tv', 'one', 'beer', 'page',
              'ai', 'uk', 'pro', 'fun', 'site', 'online', 'space', 'click', 'host'}


def now_utc():
    return datetime.now(timezone.utc)


def decode_base64(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    pad = len(s) % 4
    if pad:
        s += '=' * (4 - pad)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return ""


def is_useless_tme(url):
    if 't.me' not in url and 'telegram.me' not in url:
        return False
    if '/proxy?' in url or '/webproxy?' in url or '/joinchat/' in url:
        return True
    if '/+' in url.split('//', 1)[-1][:10]:
        return True
    path = urlparse(url).path.strip('/')
    return '/' not in path and path.lower().endswith('bot')


def is_valid_url(url, cfg):
    try:
        r = urlparse(url)
        if not all([r.scheme, r.netloc]) or r.scheme == 'tg':
            return False
        host = (r.hostname or '').lower()
        if not host or host in _BARE_TLDS:
            return False
        for d in list(cfg.blacklist_domains) + list(cfg.junk_domains):
            if host == d or host.endswith('.' + d):
                return False
        path = r.path.lower()
        # служебные URL из тел конфигов — не подписки
        if 'generate_204' in path or '/dns-query' in path:
            return False
        if host == 'github.com' and '/releases' in path:
            return False
        if path.endswith('.md'):
            return False
        if host == 'pozor.bond' and path.startswith('/status/'):
            return False
        # обёртка без целевого адреса (обрезанная ссылка)
        if host in ('p.kfwl.lol', 'ghfast.top', 'happy-decoder.cc') and len(r.path.strip('/')) < 8:
            return False
        return True
    except Exception:
        return False


def _split_glued_http(url):
    base = 8 if url.startswith('https://') else 7
    rest = url[base:]
    for proto in ('https://', 'http://'):
        i = rest.find(proto)
        if i > 0 and rest[i - 1] != '/':
            return url[:base + i]
    if url.count('@') >= 2:
        i = rest.index('@')
        head = rest[:i]
        if '/' not in head and ':' not in head:
            return url[:base + i]
    return url


def _sticky(url):
    for w in _STICKY:
        if url.endswith(w):
            url = url[:-len(w)]
    return url.rstrip('/')


def _drop_param(k, v):
    kl = k.lower()
    if kl in _TRACK_KEYS:
        return True
    return kl in _CACHE_KEYS and str(v).isdigit()


def normalize_sub_url(url):
    if 'hub.mos.ru/' in url:
        url = url.replace('/-/raw/', '/raw/')
    # p.kfwl.lol/<target> без опций отдаёт HTML-панель вместо подписки.
    # Рабочий формат: /ua=happ/os=android/<target>
    m = _KFWL_RE.match(url)
    if m:
        head, tail = m.group(1), m.group(2)
        if tail.startswith(('http://', 'https://')):
            url = head + _KFWL_HINT + tail
    try:
        p = urlsplit(url)
        if p.query:
            pairs = parse_qsl(p.query, keep_blank_values=True)
            if any(_drop_param(k, v) for k, v in pairs):
                kept = [(k, v) for k, v in pairs if not _drop_param(k, v)]
                url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(kept), p.fragment))
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
    # склейки чиним только у http(s): иначе режутся легитимные vless://...path=...https://...
    if url.startswith(('http://', 'https://')):
        url = normalize_sub_url(_sticky(_split_glued_http(url)))
    return url


def collect_url(raw, urls, cfg):
    u = clean_url(raw)
    if not u:
        return
    if 't.me' in u or 'telegram.me' in u:
        if not is_useless_tme(u):
            urls.append(u)
    elif is_valid_url(u, cfg):
        urls.append(u)


def valid_issue(url):
    if not url or '://' not in url or len(url) < 40:
        return False
    scheme, rest = url.split('://', 1)
    if not rest or rest.strip() in (',', ' ', '', '@'):
        return False
    if rest.startswith(('import', 'jitsi?datachannel@')):
        return False
    if scheme == 'qwdtt' and 'config?' in rest and 'peer=' not in rest and 'pass=' not in rest:
        return False
    return True


def split_issues(url):
    parts = re.compile(r'(?<!^)(?<!\s)(' + ISSUE_ALT + r')://', re.I).split(url)
    if len(parts) == 1:
        return [url]
    return [parts[i].lower() + '://' + parts[i + 1] for i in range(1, len(parts) - 1, 2)]


def from_text(text, cfg):
    """-> (список прокси-URI, список http/t.me ссылок)"""
    proxies = [clean_url(m.group(0)) for m in PROXY_RE.finditer(text)]
    for m in ISSUE_RE.finditer(text):
        ISSUE_URLS.add(clean_url(m.group(0)))
    urls = []
    for m in URL_RE.finditer(text):
        collect_url(m.group(0), urls, cfg)
    return proxies, urls


def from_element(el, cfg):
    proxies, urls = [], []
    if hasattr(el, 'find_all'):
        for a in el.find_all('a', href=True):
            href = a['href'].strip()
            low = href.lower()
            if any(low.startswith(s + '://') for s in PROXY_SCHEMES):
                proxies.append(clean_url(href))
            elif any(low.startswith(s + '://') for s in ISSUE_SCHEMES):
                ISSUE_URLS.add(clean_url(href))
            elif href.startswith('http'):
                collect_url(href, urls, cfg)
    # separator обязателен: без него <br> склеивался и URL получал
    # прилипший текст следующего блока — bit.ly/LimeVPN + "2 дня" -> LimeVPN2
    text = el.get_text(separator='\n') if hasattr(el, 'get_text') else str(el)
    p, u = from_text(text, cfg)
    return list(set(proxies + p)), list(set(urls + u))


def messages(html_text, cutoff, cfg):
    """-> ([(uri, дата)], [ссылки], min_id для пагинации)"""
    soup = BeautifulSoup(html_text, HTML_PARSER)
    out, urls, min_id = [], [], None
    for msg in soup.find_all('div', class_='tgme_widget_message'):
        mid = msg.get('data-post', '').rsplit('/', 1)[-1]
        if mid.isdigit():
            mid = int(mid)
            min_id = mid if min_id is None else min(min_id, mid)
        dt = now_utc()
        tag = msg.find('time')
        if tag and tag.get('datetime'):
            try:
                dt = datetime.fromisoformat(tag['datetime'].replace('Z', '+00:00'))
            except ValueError:
                pass
        if dt < cutoff:
            continue
        px, ur = from_element(msg, cfg)
        out.extend((p, dt) for p in px)
        urls.extend(ur)
    return out, urls, min_id


# ------------------------------------------------- структурные конфиги (JSON/YAML)

def _qs(params):
    return urlencode({k: str(v) for k, v in params.items() if v not in (None, '', [])})


def _b64u(s):
    return base64.b64encode(s.encode('utf-8')).decode('ascii').rstrip('=')


def _walk(obj):
    """Все dict-узлы дерева."""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _alpn(v):
    if isinstance(v, (list, tuple)):
        return ','.join(str(x) for x in v if x)
    return str(v or '')


def _vmess_uri(name, addr, port, uid, aid, scy, net, host, path, sec, sni, fp, alpn):
    d = {'v': '2', 'ps': name, 'add': str(addr), 'port': str(port), 'id': str(uid),
         'aid': str(aid or 0), 'scy': scy or 'auto', 'net': net, 'type': 'none',
         'host': host or sni or '', 'path': path or '',
         'tls': 'tls' if sec in ('tls', 'reality') else '', 'sni': sni or '', 'fp': fp or ''}
    if alpn:
        d['alpn'] = alpn
    return 'vmess://' + _b64u(json.dumps(d, ensure_ascii=False))


def _xray_to_uris(ob):
    """Xray JSON: outbounds[] с protocol/settings/streamSettings."""
    proto = str(ob.get('protocol') or '').lower()
    if proto not in ('vless', 'vmess', 'trojan', 'shadowsocks'):
        return []
    settings = ob.get('settings') or {}
    if not isinstance(settings, dict):
        return []
    st = ob.get('streamSettings') or {}
    net = str(st.get('network') or 'tcp').lower()
    if net == 'raw':
        net = 'tcp'
    sec = str(st.get('security') or '').lower()
    tls = st.get('tlsSettings') or {}
    real = st.get('realitySettings') or {}
    ws = st.get('wsSettings') or {}
    grpc = st.get('grpcSettings') or {}
    hu = st.get('httpupgradeSettings') or {}
    xh = st.get('xhttpSettings') or {}
    name = str(ob.get('tag') or ob.get('remarks') or '')
    sni = real.get('serverName') or tls.get('serverName') or ''
    fp = real.get('fingerprint') or tls.get('fingerprint') or ''
    alpn = _alpn(tls.get('alpn'))
    host = path = ''
    if net == 'ws':
        path = ws.get('path') or ''
        host = (ws.get('headers') or {}).get('Host') or ''
    elif net == 'httpupgrade':
        path = hu.get('path') or ''
        host = hu.get('host') or (hu.get('headers') or {}).get('Host') or ''
    elif net == 'xhttp':
        path = xh.get('path') or ''
        host = xh.get('host') or ''

    params = {'type': net}
    if sec in ('tls', 'reality'):
        params['security'] = sec
        if sni:
            params['sni'] = sni
        if fp:
            params['fp'] = fp
        if alpn:
            params['alpn'] = alpn
        if tls.get('allowInsecure'):
            params['allowInsecure'] = '1'
    if sec == 'reality':
        if real.get('publicKey'):
            params['pbk'] = real['publicKey']
        if real.get('shortId'):
            params['sid'] = real['shortId']
    if path:
        params['path'] = path
    if host:
        params['host'] = host
    if net == 'grpc':
        if grpc.get('serviceName'):
            params['serviceName'] = grpc['serviceName']
        if grpc.get('multiMode'):
            params['mode'] = 'multi'
    elif net == 'xhttp' and xh.get('mode'):
        params['mode'] = xh['mode']

    out = []
    if proto in ('vless', 'vmess'):
        for v in settings.get('vnext') or []:
            addr, port = v.get('address'), v.get('port')
            if not addr or not port:
                continue
            for u in v.get('users') or []:
                uid = u.get('id')
                if not uid:
                    continue
                if proto == 'vless':
                    pr = dict(params, encryption='none')
                    if u.get('flow'):
                        pr['flow'] = u['flow']
                    out.append(f'vless://{uid}@{addr}:{port}?{_qs(pr)}#{quote(name)}')
                else:
                    out.append(_vmess_uri(name, addr, port, uid, u.get('alterId'),
                                          u.get('security'), net, host, path, sec, sni, fp, alpn))
    elif proto == 'trojan':
        for s in settings.get('servers') or []:
            addr, port, pwd = s.get('address'), s.get('port'), s.get('password')
            if not (addr and port and pwd):
                continue
            pr = dict(params)
            pr.setdefault('security', 'tls')
            out.append(f"trojan://{quote(str(pwd), safe='')}@{addr}:{port}?{_qs(pr)}#{quote(name)}")
    elif proto == 'shadowsocks':
        for s in settings.get('servers') or []:
            addr, port = s.get('address'), s.get('port')
            method, pwd = s.get('method'), s.get('password')
            if not (addr and port and method and pwd):
                continue
            ui = _b64u('{}:{}'.format(method, pwd))
            out.append(f'ss://{ui}@{addr}:{port}#{quote(name)}')
    return out


def _singbox_to_uris(ob):
    """sing-box JSON: outbounds[] с type/server/server_port/tls/transport."""
    t = str(ob.get('type') or '').lower()
    addr, port = ob.get('server'), ob.get('server_port')
    if not (t and addr and port) or 'settings' in ob:
        return []
    if t in ('direct', 'block', 'dns', 'selector', 'urltest', 'hysteria'):
        return []
    tls = ob.get('tls') or {}
    tr = ob.get('transport') or {}
    net = str(tr.get('type') or 'tcp').lower()
    if net == 'raw':
        net = 'tcp'
    real = tls.get('reality') or {}
    sec = 'reality' if real.get('enabled') else ('tls' if tls.get('enabled') else '')
    sni = tls.get('server_name') or ''
    fp = (tls.get('utls') or {}).get('fingerprint') or ''
    alpn = _alpn(tls.get('alpn'))
    host = (tr.get('headers') or {}).get('Host') or ''
    path = tr.get('path') or ''
    name = str(ob.get('tag') or '')

    params = {'type': net}
    if sec:
        params['security'] = sec
        if sni:
            params['sni'] = sni
        if fp:
            params['fp'] = fp
        if alpn:
            params['alpn'] = alpn
        if tls.get('insecure'):
            params['allowInsecure'] = '1'
    if sec == 'reality':
        if real.get('public_key'):
            params['pbk'] = real['public_key']
        if real.get('short_id'):
            params['sid'] = real['short_id']
    if path:
        params['path'] = path
    if host:
        params['host'] = host
    if net == 'grpc' and tr.get('service_name'):
        params['serviceName'] = tr['service_name']

    if t == 'vless' and ob.get('uuid'):
        pr = dict(params, encryption='none')
        if ob.get('flow'):
            pr['flow'] = ob['flow']
        return [f"vless://{ob['uuid']}@{addr}:{port}?{_qs(pr)}#{quote(name)}"]
    if t == 'vmess' and ob.get('uuid'):
        return [_vmess_uri(name, addr, port, ob['uuid'], ob.get('alter_id'),
                           ob.get('security'), net, host, path, sec, sni, fp, alpn)]
    if t == 'trojan' and ob.get('password'):
        pr = dict(params)
        pr.setdefault('security', 'tls')
        return [f"trojan://{quote(str(ob['password']), safe='')}@{addr}:{port}?{_qs(pr)}#{quote(name)}"]
    if t == 'shadowsocks' and ob.get('password') and ob.get('method'):
        ui = _b64u('{}:{}'.format(ob['method'], ob['password']))
        return [f'ss://{ui}@{addr}:{port}#{quote(name)}']
    if t == 'hysteria2' and ob.get('password'):
        pr = {'sni': sni}
        if tls.get('insecure'):
            pr['insecure'] = '1'
        obfs = ob.get('obfs') or {}
        if obfs.get('type'):
            pr['obfs'] = obfs['type']
            pr['obfs-password'] = obfs.get('password') or ''
        return [f"hysteria2://{quote(str(ob['password']), safe='')}@{addr}:{port}?{_qs(pr)}#{quote(name)}"]
    if t == 'tuic' and ob.get('uuid'):
        pr = {'sni': sni, 'congestion_control': ob.get('congestion_control') or 'bbr',
              'udp_relay_mode': ob.get('udp_relay_mode') or 'native'}
        if tls.get('insecure'):
            pr['allow_insecure'] = '1'
        if alpn:
            pr['alpn'] = alpn
        pwd = ob.get('password') or ''
        return [f"tuic://{ob['uuid']}:{quote(str(pwd), safe='')}@{addr}:{port}?{_qs(pr)}#{quote(name)}"]
    return []


def _clash_to_uris(p):
    """Clash YAML/JSON: proxies[] с type/server/port."""
    t = str(p.get('type') or '').lower()
    addr, port = p.get('server'), p.get('port')
    if not (t and addr and port) or 'protocol' in p:
        return []
    name = str(p.get('name') or '')
    net = str(p.get('network') or 'tcp').lower()
    if net == 'raw':
        net = 'tcp'
    ro = p.get('reality-opts') or {}
    sec = 'reality' if ro else ('tls' if p.get('tls') else '')
    sni = p.get('servername') or p.get('server-name') or p.get('sni') or ''
    fp = p.get('client-fingerprint') or ''
    alpn = _alpn(p.get('alpn'))
    ws = p.get('ws-opts') or {}
    grpc = p.get('grpc-opts') or {}
    hu = p.get('http-upgrade-opts') or {}
    xh = p.get('xhttp-opts') or {}
    host = path = ''
    if net == 'ws':
        path = ws.get('path') or ''
        host = (ws.get('headers') or {}).get('Host') or ''
    elif net == 'httpupgrade':
        path = hu.get('path') or ''
        host = (hu.get('headers') or {}).get('Host') or ''
    elif net == 'xhttp':
        path = xh.get('path') or ''
        host = xh.get('host') or ''

    params = {'type': net}
    if sec:
        params['security'] = sec
        if sni:
            params['sni'] = sni
        if fp:
            params['fp'] = fp
        if alpn:
            params['alpn'] = alpn
        if p.get('skip-cert-verify'):
            params['allowInsecure'] = '1'
    if ro:
        if ro.get('public-key'):
            params['pbk'] = ro['public-key']
        if ro.get('short-id'):
            params['sid'] = ro['short-id']
    if path:
        params['path'] = path
    if host:
        params['host'] = host
    if net == 'grpc' and grpc.get('grpc-service-name'):
        params['serviceName'] = grpc['grpc-service-name']
        if grpc.get('grpc-mode') == 'multi':
            params['mode'] = 'multi'

    if t == 'vless' and p.get('uuid'):
        pr = dict(params, encryption='none')
        if p.get('flow'):
            pr['flow'] = p['flow']
        return [f"vless://{p['uuid']}@{addr}:{port}?{_qs(pr)}#{quote(name)}"]
    if t == 'vmess' and p.get('uuid'):
        return [_vmess_uri(name, addr, port, p['uuid'], p.get('alterId'),
                           p.get('cipher'), net, host, path, sec, sni, fp, alpn)]
    if t == 'trojan' and p.get('password'):
        pr = dict(params)
        pr.setdefault('security', 'tls')
        return [f"trojan://{quote(str(p['password']), safe='')}@{addr}:{port}?{_qs(pr)}#{quote(name)}"]
    if t == 'ss' and p.get('password') and p.get('cipher'):
        ui = _b64u('{}:{}'.format(p['cipher'], p['password']))
        return [f'ss://{ui}@{addr}:{port}#{quote(name)}']
    if t in ('hysteria2', 'hy2') and p.get('password'):
        pr = {'sni': sni}
        if p.get('skip-cert-verify'):
            pr['insecure'] = '1'
        if p.get('obfs'):
            pr['obfs'] = p['obfs']
            pr['obfs-password'] = p.get('obfs-password') or ''
        return [f"hysteria2://{quote(str(p['password']), safe='')}@{addr}:{port}?{_qs(pr)}#{quote(name)}"]
    if t == 'tuic' and p.get('uuid'):
        pr = {'sni': sni, 'congestion_control': p.get('congestion-controller') or 'bbr',
              'udp_relay_mode': p.get('udp-relay-mode') or 'native'}
        if p.get('skip-cert-verify'):
            pr['allow_insecure'] = '1'
        if alpn:
            pr['alpn'] = alpn
        pwd = p.get('password') or ''
        return [f"tuic://{p['uuid']}:{quote(str(pwd), safe='')}@{addr}:{port}?{_qs(pr)}#{quote(name)}"]
    return []


def _from_structured(body):
    """Xray / Clash / sing-box конфиги -> список URI."""
    s = body.lstrip()
    data = None
    if s.startswith('{') or s.startswith('['):
        try:
            data = json.loads(s)
        except Exception:
            data = None
    if data is None and ('proxies:' in body or 'outbounds:' in body):
        try:
            data = yaml.safe_load(body)
        except Exception:
            data = None
    if data is None:
        return []

    out = []
    # 1) готовые URI и base64-блоки внутри строковых значений
    for v in _strings(data):
        if '://' in v and PROXY_RE.search(v):
            out.extend(clean_url(m.group(0)) for m in PROXY_RE.finditer(v))
        elif len(v) > 100 and _B64_FULL.match(v):
            dec = decode_base64(v)
            if dec:
                out.extend(clean_url(m.group(0)) for m in PROXY_RE.finditer(dec))
    # 2) конвертация описаний нод в URI
    for ob in _walk(data):
        for fn in (_xray_to_uris, _singbox_to_uris, _clash_to_uris):
            try:
                got = fn(ob)
            except Exception:
                got = []
            if got:
                out.extend(got)
                break
    seen, uniq = set(), []
    for u in out:
        if u and u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def _from_html(body):
    """Ключи из HTML-панели: атрибуты кнопок + base64-блоки."""
    raw = html_mod.unescape(body)
    out, seen = [], set()
    for m in _URI_IN_HTML.finditer(raw):
        u = clean_url(m.group(0))
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    if not out:
        for m in _B64_BLOB.finditer(raw):
            dec = decode_base64(m.group(0))
            if not dec:
                continue
            for p in PROXY_RE.findall(dec):
                u = clean_url(p)
                if u and u not in seen:
                    seen.add(u)
                    out.append(u)
    return out


def from_subscription(text, cfg):
    decoded = decode_base64(text)
    body = decoded if decoded and len(decoded) > 50 else text
    found = [clean_url(p) for p in PROXY_RE.findall(body)]
    if not found:
        found = _from_structured(body)
        if found:
            log.debug(f'🧩 ключи из структурного конфига (Xray/Clash/sing-box): {len(found)}')
    if not found and _HTML_HINT.search(body):
        found = _from_html(body)
        if found:
            log.debug(f'🧩 ключи извлечены из HTML-панели: {len(found)}')
    for m in ISSUE_RE.finditer(body):
        ISSUE_URLS.add(clean_url(m.group(0)))
    log.STATS['sub_links'] += len(found)
    return found


def sub_key(url):
    m = TME_RE.match(url)
    if m:
        chan, mid = m.group(1).lower(), m.group(2)
        return f'tg:{chan}/{mid}' if mid else f'tg:{chan}'
    return url.rstrip('/')
