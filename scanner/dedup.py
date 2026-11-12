import re
from urllib.parse import parse_qsl, unquote, urlsplit

from .extract import SCHEMES_ALT
from .wl import roots_match

IGNORED = {'fp', 'alpn', 'extra', 'headertype', 'encryption', 'allowinsecure',
           'insecure', 'fm', 'packetencoding', 'spx', 'ed'}
DEDUP_SCHEMES = {'vless', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic'}

# Расклейка ТОЛЬКО внутри имени (фрагмента). Тело и запрос не режем никогда.
# ВАЖНО: finditer (неперекрывающиеся матчи), а не zero-width split:
# внутри 'vless://' есть подстрока 'ss://', и split находил её как второй матч,
# превращая хвост в 'ss://uuid@host' — ссылка ломалась.
_SCHEME_RE = re.compile(r'(?:' + SCHEMES_ALT + r')://', re.I)


def _link_starts(frag):
    """Позиции начал вклеенных ссылок внутри имени.
    Матч принимается, только если за схемой идёт структура ссылки —
    это отсекает 'wss://' и прочий мусор в именах."""
    starts = []
    for m in _SCHEME_RE.finditer(frag):
        scheme = m.group(0)[:-3].lower()
        rest = frag[m.end():m.end() + 400]
        rest = re.split(r'\s', rest, 1)[0]      # до первого пробела
        rest = rest.split('#', 1)[0]            # тело ссылки, без имени
        if scheme in ('vmess', 'happ'):
            # у этих схем тело — base64, без '@' и ':'
            if len(rest) >= 20:
                starts.append(m.start())
        elif '@' in rest and ':' in rest:
            starts.append(m.start())
    return starts


def split_uri(uri):
    """-> (варианты головы, вклеенные хвосты).
    Оригинал всегда присутствует как запасной вариант — потеря ключа невозможна."""
    head, sep, frag = uri.partition('#')
    if not sep:
        return [uri], []
    starts = _link_starts(frag)
    if not starts:
        return [uri], []
    name = frag[:starts[0]]
    clean = head + ('#' + name if name else '')
    bounds = starts + [len(frag)]
    tails = [frag[bounds[i]:bounds[i + 1]] for i in range(len(starts))]
    tails = [t for t in tails if t]
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
    """-> (представители, {представитель: все его дубликаты}).
    Дубликаты нужны, чтобы отдать кредит всем источникам конфига."""
    groups = {}
    for u in sorted(set(uris)):
        groups.setdefault(config_key(u), []).append(u)
    rep_members = {}
    for g in groups.values():
        rep = max(g, key=lambda x: rank(x, cfg))
        rep_members[rep] = g
    reps = list(rep_members.keys())
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
