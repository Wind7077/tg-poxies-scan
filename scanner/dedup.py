import re
from urllib.parse import parse_qsl, unquote, urlsplit

from .extract import PROXY_SCHEMES
from .wl import roots_match

IGNORED = {'fp', 'alpn', 'extra', 'headertype', 'encryption', 'allowinsecure',
           'insecure', 'fm', 'packetencoding', 'spx', 'ed'}
DEDUP_SCHEMES = {'vless', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic'}

# Расклейка ТОЛЬКО внутри имени. Тело/запрос не режем никогда:
# внутри path/host встречается wss://, а он содержит ss:// — прежняя версия
# резала там ссылку пополам и теряла десятки тысяч ключей (WL=0).
# Порядок альтернатив важен: 'vless' должен стоять перед 'ss', иначе подстрока
# 'ss://' внутри 'vless://' ошибочно принимается за границу склейки. Граница —
# только совпадение схемы, непосредственно следующее за предыдущей границей.
_SPLIT_SCHEMES = '|'.join(sorted(PROXY_SCHEMES, key=len, reverse=True))
_BOUNDARY_RE = re.compile(r'(?:' + _SPLIT_SCHEMES + r')://', re.I)


def split_uri(uri):
    """-> (варианты головы, вклеенные хвосты). Оригинал всегда запасной вариант."""
    head, sep, frag = uri.partition('#')
    if not sep or not _BOUNDARY_RE.search(frag):
        return [uri], []
    pos, i = [], 0
    while True:
        m = _BOUNDARY_RE.search(frag, i)
        if not m:
            break
        pos.append(m.start())
        i = m.end()
    pieces = [frag[:pos[0]]] + [frag[i:] for i in pos]
    name = pieces[0]
    clean = head + ('#' + name if name else '')
    tails = [t for t in pieces[1:] if '@' in t and ':' in t]
    variants = [clean] + ([uri] if clean != uri else [])
    return variants, tails


def parts(uri):
    try:
        u = urlsplit(uri)
        q = {k.lower(): v for k, v in parse_qsl(u.query)}
        return (u.scheme.lower(), u.username or '', u.password or '',
                (u.hostname or '').lower(), u.port or 0,
                u.path.rstrip('/'), q, unquote(u.fragment))
    except ValueError:
        return None


def config_key(uri):
    p = parts(uri)
    if not p or p[0] not in DEDUP_SCHEMES or not p[3]:
        return uri
    scheme, user, pwd, host, port, path, q, _ = p
    q = {k: v for k, v in q.items() if v and k not in IGNORED}
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
    return (scheme, user, pwd, host, port, path, tuple(sorted(q.items())))


def rank(uri, cfg):
    p = parts(uri)
    if not p:
        return (False, 0)
    hit = roots_match({'name': p[7], 'server': p[3], 'sni': p[6].get('sni', '')}, cfg)
    return (hit, len(p[7]))


def dedupe(uris, cfg, per_endpoint=None):
    """-> (представители, {представитель: все дубликаты})"""
    groups = {}
    for u in sorted(set(uris)):
        groups.setdefault(config_key(u), []).append(u)
    rep_members = {}
    for g in groups.values():
        rep = max(g, key=lambda x: rank(x, cfg))
        rep_members[rep] = g
    reps = list(rep_members)
    cap = cfg.limits.per_endpoint if per_endpoint is None else per_endpoint
    if cap and int(cap) > 0:
        per, capped = {}, []
        for u in sorted(reps, key=lambda x: rank(x, cfg), reverse=True):
            p = parts(u)
            ep = (p[3], p[4]) if p and p[3] else u
            per[ep] = per.get(ep, 0) + 1
            if per[ep] <= int(cap):
                capped.append(u)
        reps = capped
    return reps, {r: rep_members[r] for r in reps}
