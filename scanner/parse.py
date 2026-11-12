import json
import re
from urllib.parse import parse_qs, unquote

from .extract import decode_base64

UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
SID_RE = re.compile(r'^(?:[0-9a-fA-F]{2}){0,8}$')
NETWORKS = {'tcp', 'ws', 'grpc', 'h2', 'http', 'httpupgrade', 'raw', 'xhttp'}
FPS = {'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'qq'}
FLOWS = {'xtls-rprx-vision', 'xtls-rprx-vision-udp443'}
CIPHERS = {
    'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'rc4-md5', 'chacha20', 'chacha20-ietf',
    'xchacha20', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
    'none', 'plain', 'dummy', 'auto',
}
VMESS_CIPHERS = ('auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero')


def hostport(hp):
    hp = hp.split('/', 1)[0].strip()
    if hp.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)$', hp)
        if not m:
            return None
        host, port = m.group(1), int(m.group(2))
    else:
        if ':' not in hp:
            return None
        host, ps = hp.rsplit(':', 1)
        if not host or not ps.isdigit():
            return None
        port = int(ps)
    return (host, port) if 1 <= port <= 65535 else None


def _truthy(v):
    return str(v).lower() in ('1', 'true', 'yes')


def _transport(res, q):
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
        svc = q.get('serviceName', [''])[0]
        if svc:
            res['grpc-opts'] = {'grpc-service-name': svc}
        if q.get('mode', [''])[0] == 'multi':
            res.setdefault('grpc-opts', {})['grpc-mode'] = 'multi'
    elif nt == 'httpupgrade':
        o = {'path': path if path.startswith('/') else '/' + (path or '')}
        if host:
            o['headers'] = {'Host': host}
        res['http-upgrade-opts'] = o
    elif nt == 'xhttp':
        o = {}
        if path:
            o['path'] = path
        if host:
            o['host'] = host
        if o:
            res['xhttp-opts'] = o


def parse(uri):
    def s1(q, k, d=''):
        v = q.get(k)
        return v[0] if v and v[0] else d

    try:
        scheme, rest = uri.split('://', 1)
        scheme = scheme.lower()
        if scheme == 'happ':
            return None

        if scheme in ('vless', 'trojan'):
            userinfo, rest2 = rest.split('@', 1)
            hp_params, _, name_part = rest2.partition('#')
            hp, _, qs = hp_params.partition('?')
            hp2 = hostport(hp)
            if not hp2:
                return None
            h, p = hp2
            q = parse_qs(qs)
            name = unquote(name_part).strip() or f'{scheme.upper()}-{h}'
            nt = s1(q, 'type', 'tcp')
            if nt == 'raw':
                nt = 'tcp'
            if scheme == 'vless':
                res = {'name': name, 'type': 'vless', 'server': h, 'port': p,
                       'uuid': unquote(userinfo), 'network': nt, 'udp': True}
            else:
                res = {'name': name, 'type': 'trojan', 'server': h, 'port': p,
                       'password': unquote(userinfo), 'network': nt, 'udp': True, 'tls': True}
            security = s1(q, 'security', 'tls' if scheme == 'trojan' else '')
            sni = s1(q, 'sni') or s1(q, 'peer')
            fp = s1(q, 'fp')
            if security == 'reality':
                pbk, sid = s1(q, 'pbk'), s1(q, 'sid').strip()
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
            if cipher not in VMESS_CIPHERS:
                cipher = 'auto'
            res = {'name': d.get('ps') or f"VM-{d.get('add', 'unknown')}", 'type': 'vmess',
                   'server': d.get('add'), 'port': port, 'uuid': d.get('id', ''),
                   'alterId': int(str(d.get('aid', 0) or 0)), 'cipher': cipher,
                   'tls': d.get('tls') == 'tls', 'network': net, 'udp': True}
            if res['tls']:
                res['server-name'] = d.get('sni') or d.get('host') or res['server']
            path, host = d.get('path') or '', d.get('host') or ''
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
                userinfo, hp = body.rsplit('@', 1)
                userinfo = unquote(userinfo)
                if ':' in userinfo:
                    cipher, password = userinfo.split(':', 1)
                else:
                    dec = decode_base64(userinfo)
                    if ':' not in dec:
                        return None
                    cipher, password = dec.split(':', 1)
            else:
                dec = decode_base64(body)
                if '@' not in dec or ':' not in dec:
                    return None
                userinfo, hp = dec.rsplit('@', 1)
                if ':' not in userinfo:
                    return None
                cipher, password = userinfo.split(':', 1)
            hp2 = hostport(hp)
            if not hp2 or not password:
                return None
            h, p = hp2
            if cipher == 'chacha20-poly1305':
                cipher = 'chacha20-ietf-poly1305'
            return {'name': name or f'SS-{h}', 'type': 'ss', 'server': h, 'port': p,
                    'cipher': cipher, 'password': password, 'udp': True}

        if scheme in ('hysteria', 'hysteria2', 'hy2'):
            pa, _, name_part = rest.partition('#')
            auth, _, qs = pa.partition('?')
            if '@' in auth:
                password, hp = auth.rsplit('@', 1)
            else:
                password, hp = '', auth
            hp2 = hostport(hp)
            if not hp2:
                return None
            h, p = hp2
            q = parse_qs(qs)
            ptype = 'hysteria2' if scheme in ('hysteria2', 'hy2') else 'hysteria'
            res = {'name': unquote(name_part).strip() or f'HY-{h}', 'type': ptype,
                   'server': h, 'port': p, 'udp': True}
            password = unquote(password)
            res['password' if ptype == 'hysteria2' else 'auth-str'] = password
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
            hp, _, qs = hp_params.partition('?')
            hp2 = hostport(hp)
            if not hp2:
                return None
            h, p = hp2
            uuid, _, password = unquote(userinfo).partition(':')
            q = parse_qs(qs)
            res = {'name': unquote(name_part).strip() or f'TUIC-{h}', 'type': 'tuic',
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


def sanitize(p):
    net = p.get('network')
    if net not in NETWORKS:
        p['network'] = net = 'tcp'
    for n, key in (('ws', 'ws-opts'), ('grpc', 'grpc-opts'), ('h2', 'h2-opts'),
                   ('http', 'http-opts'), ('xhttp', 'xhttp-opts'),
                   ('httpupgrade', 'http-upgrade-opts')):
        if net != n and key in p:
            del p[key]
    if isinstance(p.get('ws-opts'), dict):
        path = p['ws-opts'].get('path', '/')
        if not isinstance(path, str) or not path.startswith('/'):
            p['ws-opts']['path'] = '/'
    fp = p.get('client-fingerprint')
    if fp and fp not in FPS:
        p['client-fingerprint'] = 'chrome'
    elif not fp and p.get('tls'):
        p['client-fingerprint'] = 'chrome'
    flow = p.get('flow')
    if flow and (flow not in FLOWS or p.get('type') != 'vless'):
        del p['flow']
    if p.get('tls'):
        sn = p.get('server-name') or p.get('servername') or p.get('sni') or p.get('server', '')
        p['server-name'] = sn
        p.pop('servername', None)
    if isinstance(p.get('uuid'), str):
        p['uuid'] = re.sub(r'[^0-9a-fA-F-]', '', p['uuid'])
    return p


def validate(p):
    if not isinstance(p, dict):
        return False, 'not-dict'
    t, srv, port, name = p.get('type'), p.get('server'), p.get('port'), p.get('name')
    if not name or not isinstance(name, str):
        return False, 'name'
    if not srv or not isinstance(srv, str):
        return False, 'server'
    if any(c.isspace() for c in srv) or any(c in srv for c in '/%@'):
        return False, 'server-chars'
    if not isinstance(port, int) or not 1 <= port <= 65535:
        return False, 'port'
    if t in ('vless', 'vmess'):
        if not UUID_RE.match(p.get('uuid') or ''):
            return False, 'uuid'
        if p.get('network') not in NETWORKS:
            return False, 'network'
        if t == 'vmess':
            if not isinstance(p.get('alterId'), int) or p['alterId'] < 0:
                return False, 'alterId'
            if p.get('cipher') not in VMESS_CIPHERS:
                return False, 'vmess-cipher'
        if t == 'vless' and p.get('flow') and not p.get('tls'):
            return False, 'flow-no-tls'
    elif t in ('trojan', 'hysteria2'):
        if not p.get('password'):
            return False, 'password'
    elif t == 'ss':
        if not p.get('password'):
            return False, 'password'
        if p.get('cipher') not in CIPHERS:
            return False, 'cipher'
    elif t == 'hysteria':
        if not (p.get('auth-str') or p.get('password')):
            return False, 'auth'
    elif t == 'tuic':
        if not UUID_RE.match(p.get('uuid') or ''):
            return False, 'uuid'
    else:
        return False, 'type'
    if 'reality-opts' in p:
        ro = p['reality-opts']
        if not ro.get('public-key'):
            return False, 'reality-pbk'
        sid = ro.get('short-id', '')
        if sid and not SID_RE.match(str(sid)):
            return False, 'reality-sid'
        if not p.get('server-name'):
            return False, 'reality-sni'
    return True, ''


def fail_reason(uri):
    scheme, _, rest = uri.partition('://')
    s = scheme.lower()[:12]
    if not rest:
        return f'{s}:пусто'
    if s in ('vless', 'trojan', 'tuic'):
        if '@' not in rest:
            return f'{s}:нет-@'
        hp = rest.split('@', 1)[1].partition('#')[0].partition('?')[0]
        if hostport(hp) is None:
            return f'{s}:host-port'
        low = rest.lower()
        if s == 'vless' and 'security=reality' in low and 'pbk=' not in low:
            return f'{s}:reality-без-pbk'
        return f'{s}:прочее'
    if s == 'vmess':
        return 'vmess:json-b64'
    if s == 'ss':
        return 'ss:формат'
    return f'{s}:прочее'
