import base64
import re
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlsplit, urlunsplit

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

ISSUE_URLS = set()

_AMP_RE = re.compile(r'&(?:amp|#0*38|#x0*26);', re.I)
_TRACK_KEYS = {'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
               'fbclid', 'gclid', 'yclid', 'ysclid', 'ref_type', 'erid'}
_STICKY = ['Gemini', 'Gemini:', 'Claude', 'ChatGPT']
TME_RE = re.compile(r'https?://(?:t\.me|telegram\.me)/(?:s/)?([a-zA-Z0-9_]+)(?:/(\d+))?')


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
        for d in list(cfg.blacklist_domains) + list(cfg.junk_domains):
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


def normalize_sub_url(url):
    if 'hub.mos.ru/' in url:
        url = url.replace('/-/raw/', '/raw/')
    try:
        p = urlsplit(url)
        if p.query:
            pairs = parse_qsl(p.query, keep_blank_values=True)
            if any(k.lower() in _TRACK_KEYS for k, _ in pairs):
                kept = [(k, v) for k, v in pairs if k.lower() not in _TRACK_KEYS]
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
    text = el.get_text() if hasattr(el, 'get_text') else str(el)
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


def from_subscription(text, cfg):
    decoded = decode_base64(text)
    body = decoded if decoded and len(decoded) > 50 else text
    found = [clean_url(p) for p in PROXY_RE.findall(body)]
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
