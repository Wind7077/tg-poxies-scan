"""Экспорт списка прокси в Xray-JSON для Streisand (iOS).

Читает proxy.txt (+ proxy-best.txt в приоритете), собирает полный конфиг
с fakedns, DoH, фрагментацией, observatory и balancer'ом leastPing.

DNS: NextDNS и Яндекс.DoH первыми в списке, дальше резерв. По умолчанию
запросы идут параллельно — побеждает быстрейший. Флаг --sequential-dns
включает строгий приоритет по порядку (медленнее, но NextDNS определяющий).

Запуск:
    python make_streisand.py                          # NextDNS ac3755 + Яндекс
    python make_streisand.py --nextdns abc123         # свой профиль NextDNS
    python make_streisand.py --nextdns ''             # без NextDNS
    python make_streisand.py --sequential-dns         # строгий приоритет DNS
    python make_streisand.py --max 300 --tcp          # старые имена network/settings
    python make_streisand.py --mode all_proxy         # весь трафик через туннель
    python make_streisand.py --input proxy-all.txt --out all-streisand.json
"""
import argparse
import json
import sys
from pathlib import Path

from scanner.parse import parse, sanitize, validate

# Xray не поддерживает эти протоколы — в экспорт не берём
SUPPORTED = {'vless', 'vmess', 'trojan', 'ss'}

NEXTDNS_IPS = ['45.90.28.73', '45.90.30.73']
YANDEX_IPS = ['77.88.8.8', '77.88.8.1']
YANDEX_DOH = 'https://common.dot.dns.yandex.net/dns-query'

# Бутстрап-IP DoH-хостов: без них DoH не сможет сам себя отрезолвить
DNS_HOSTS = {
    'localhost': '127.0.0.1',
    'dns.nextdns.io': NEXTDNS_IPS,
    'common.dot.dns.yandex.net': YANDEX_IPS,
    'dns.google': ['8.8.8.8', '8.8.4.4'],
    'cloudflare-dns.com': ['1.1.1.1', '1.0.0.1'],
    'dns.quad9.net': ['9.9.9.9', '149.112.112.112'],
    'dns.adguard-dns.com': ['94.140.14.14', '94.140.15.15'],
    'freedns.controld.com': ['76.76.2.0', '76.76.10.0'],
    'doh.opendns.com': ['208.67.222.222', '208.67.220.220'],
    'dns.mullvad.net': ['194.242.2.2'],
    'doh.libredns.gr': ['116.202.176.26'],
    'dns.hostux.net': ['46.226.108.173', '46.226.109.82'],
    'blank.dnsforge.de': ['138.199.149.249', '78.47.71.194'],
}

# Порядок важен при --sequential-dns; в параллельном режиме — просто список
BOOTSTRAP_IPS = (
    NEXTDNS_IPS + YANDEX_IPS +
    ['1.1.1.1', '8.8.8.8', '9.9.9.9', '94.140.14.14', '208.67.222.222']
)

# Общие резолверы: NextDNS и Яндекс первыми, дальше резерв
RESERVE_DOH = [
    'https://cloudflare-dns.com/dns-query',
    'https://dns.google/dns-query',
    'https://dns.quad9.net/dns-query',
    'https://dns.adguard-dns.com/dns-query',
    'https://freedns.controld.com/p0',
    'https://doh.opendns.com/dns-query',
    'https://dns.mullvad.net/dns-query',
    'https://doh.libredns.gr/dns-query',
    'https://dns.hostux.net/dns-query',
    'https://blank.dnsforge.de/dns-query',
]


def read_uris(path):
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            out.append(line)
    return out


def srv_key(p):
    return (p.get('type'), str(p.get('server', '')).lower(), p.get('port'),
            p.get('uuid') or p.get('password') or '', p.get('cipher') or '')


def collect(inputs, limit):
    """best-список в приоритете, затем основной; дедуп по серверу."""
    seen, out = set(), []
    for path in inputs:
        for uri in read_uris(path):
            p = parse(uri)
            if not p:
                continue
            p = sanitize(p)
            if p.get('type') not in SUPPORTED:
                continue
            if not validate(p)[0]:
                continue
            k = srv_key(p)
            if k in seen:
                continue
            seen.add(k)
            out.append(p)
            if limit and len(out) >= limit:
                return out
    return out


def _stream(p, args):
    net = str(p.get('network') or 'tcp').lower()
    if net in ('tcp', 'raw'):
        net = 'tcp' if args.tcp else 'raw'
    st = {'network': net}

    sockopt = {'tcpKeepAliveIdle': 300, 'tcpKeepAliveInterval': 60}
    ro = p.get('reality-opts') or {}
    # фрагментация ClientHello ломает REALITY — на такие ноды не ставим
    if args.fragment and not ro:
        sockopt['dialerProxy'] = 'fragment'
    st['sockopt'] = sockopt

    ws = p.get('ws-opts') or {}
    grpc = p.get('grpc-opts') or {}
    hu = p.get('http-upgrade-opts') or {}
    xh = p.get('xhttp-opts') or {}
    if net == 'ws':
        wso = {'path': ws.get('path') or '/'}
        host = (ws.get('headers') or {}).get('Host')
        if host:
            wso['headers'] = {'Host': host}
        st['wsSettings'] = wso
    elif net == 'grpc':
        st['grpcSettings'] = {
            'serviceName': grpc.get('grpc-service-name') or '',
            'multiMode': grpc.get('grpc-mode') == 'multi',
        }
    elif net == 'httpupgrade':
        hus = {'path': hu.get('path') or '/'}
        host = (hu.get('headers') or {}).get('Host')
        if host:
            hus['host'] = host
        st['httpupgradeSettings'] = hus
    elif net == 'xhttp':
        st['xhttpSettings'] = {'path': xh.get('path') or '/',
                               'mode': xh.get('mode') or 'auto'}
        if xh.get('host'):
            st['xhttpSettings']['host'] = xh['host']
    else:
        key = 'tcpSettings' if args.tcp else 'rawSettings'
        st[key] = {'header': {'type': 'none'}}

    sni = p.get('server-name') or p.get('servername') or p.get('sni') or ''
    fp = p.get('client-fingerprint') or 'chrome'
    alpn = p.get('alpn') or []
    if isinstance(alpn, str):
        alpn = [x.strip() for x in alpn.split(',') if x.strip()]

    if ro:
        st['security'] = 'reality'
        rs = {'serverName': sni or p.get('server'), 'fingerprint': fp,
              'publicKey': ro.get('public-key') or ''}
        if ro.get('short-id'):
            rs['shortId'] = str(ro['short-id'])
        st['realitySettings'] = rs
    elif p.get('tls'):
        st['security'] = 'tls'
        ts = {'fingerprint': fp}
        if sni:
            ts['serverName'] = sni
        if alpn:
            ts['alpn'] = alpn
        if p.get('skip-cert-verify'):
            ts['allowInsecure'] = True
        st['tlsSettings'] = ts
    else:
        st['security'] = 'none'
    return st


def outbound(p, tag, args):
    t = p['type']
    addr, port = p['server'], int(p['port'])
    if t in ('vless', 'vmess'):
        user = {'id': p['uuid']}
        if t == 'vless':
            user['encryption'] = 'none'
            if p.get('flow'):
                user['flow'] = p['flow']
        else:
            user['alterId'] = int(p.get('alterId') or 0)
            user['security'] = p.get('cipher') or 'auto'
        settings = {'vnext': [{'address': addr, 'port': port, 'users': [user]}]}
    elif t == 'trojan':
        settings = {'servers': [{'address': addr, 'port': port,
                                 'password': str(p['password'])}]}
    elif t == 'ss':
        settings = {'servers': [{'address': addr, 'port': port,
                                 'method': p['cipher'], 'password': str(p['password'])}]}
    else:
        return None
    return {'tag': tag, 'protocol': t, 'settings': settings,
            'streamSettings': _stream(p, args)}


def build_dns(args):
    hosts = dict(DNS_HOSTS)
    if not args.nextdns:
        hosts.pop('dns.nextdns.io', None)
    full = [f'full:{h}' for h in hosts if h != 'localhost']

    servers = ['fakedns']
    #平原-резолверы только для имён самих DoH-хостов (skipFallback)
    for ip in BOOTSTRAP_IPS:
        servers.append({'address': f'tcp+local://{ip}:53', 'domains': full,
                        'skipFallback': True, 'queryStrategy': 'UseIPv4',
                        'timeoutMs': 4000})
    # общие резолверы
    if args.nextdns:
        servers.append(f'https://dns.nextdns.io/{args.nextdns}')
    servers.append(YANDEX_DOH)
    servers.extend(RESERVE_DOH)

    return {'hosts': hosts, 'servers': servers, 'queryStrategy': 'UseIPv4',
            'disableCache': False, 'serveStale': True, 'useSystemHosts': True,
            'enableParallelQuery': bool(args.parallel_dns),
            'tag': 'dns-remote', 'disableFallbackIfMatch': True}


def build_routing(prefix, first_tag, mode):
    rules = [
        {'type': 'field', 'inboundTag': ['dns-remote'], 'balancerTag': f'{prefix}auto'},
        {'type': 'field', 'inboundTag': ['dns-in'], 'outboundTag': 'dns-out'},
        {'type': 'field', 'domain': ['full:localhost', 'domain:local', 'domain:lan',
                                     'regexp:^[^.]+$'], 'outboundTag': 'direct'},
        {'type': 'field', 'ip': ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12',
                                 '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10',
                                 '::1/128', 'fc00::/7', 'fe80::/10'],
         'outboundTag': 'direct'},
    ]
    if mode == 'ru_direct':
        rules.append({'type': 'field',
                      'domain': ['domain:ru', 'domain:xn--p1ai', 'domain:su',
                                 'geosite:category-ru'],
                      'outboundTag': 'direct'})
        rules.append({'type': 'field', 'ip': ['geoip:ru'], 'outboundTag': 'direct'})
    rules.append({'type': 'field', 'network': 'tcp,udp', 'balancerTag': f'{prefix}auto'})
    return {'domainStrategy': 'IPIfNonMatch', 'domainMatcher': 'hybrid',
            'balancers': [{'tag': f'{prefix}auto', 'selector': [prefix],
                           'fallbackTag': first_tag, 'strategy': {'type': 'leastPing'}}],
            'rules': rules}


def build(proxies, args):
    prefix = args.prefix
    nodes = []
    for i, p in enumerate(proxies, 1):
        ob = outbound(p, f'{prefix}{i:03d}', args)
        if ob:
            nodes.append(ob)
    if not nodes:
        return None
    first_tag = nodes[0]['tag']

    service = [
        {'tag': 'fragment', 'protocol': 'freedom',
         'settings': {'fragment': {'packets': '1-3', 'length': '50-100',
                                   'interval': '10-20', 'maxSplit': '10'},
                      'noises': [{'type': 'rand', 'packet': '50-150',
                                  'delay': '10-50'}]}},
        {'tag': 'direct', 'protocol': 'freedom',
         'settings': {'domainStrategy': 'UseIPv4'}},
        {'tag': 'block', 'protocol': 'blackhole',
         'settings': {'response': {'type': 'http'}}},
        {'tag': 'dns-out', 'protocol': 'dns', 'settings': {'network': 'tcp,udp'}},
    ]
    sniff = {'enabled': True, 'destOverride': ['http', 'tls', 'quic', 'fakedns'],
             'metadataOnly': False}
    return {
        'log': {'loglevel': 'warning'},
        'dns': build_dns(args),
        'fakedns': [{'ipPool': '198.18.0.0/16', 'poolSize': 65535}],
        'inbounds': [
            {'tag': 'socks-in', 'listen': '127.0.0.1', 'port': 10808,
             'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True},
             'sniffing': sniff},
            {'tag': 'http-in', 'listen': '127.0.0.1', 'port': 10809,
             'protocol': 'http', 'settings': {}, 'sniffing': sniff},
            {'tag': 'dns-in', 'listen': '127.0.0.1', 'port': 10853,
             'protocol': 'dokodemo-door',
             'settings': {'address': '1.1.1.1', 'port': 53, 'network': 'tcp,udp'}},
        ],
        'outbounds': nodes + service,
        'observatory': {'subjectSelector': [prefix],
                        'probeURL': 'https://www.gstatic.com/generate_204',
                        'probeInterval': '5m', 'enableConcurrency': True},
        'routing': build_routing(prefix, first_tag, args.mode),
    }


def main():
    ap = argparse.ArgumentParser(description='Экспорт прокси в Streisand Xray-JSON')
    ap.add_argument('--input', default='proxy.txt')
    ap.add_argument('--best', default='proxy-best.txt',
                    help='список, который берётся в приоритете (пустая строка — отключить)')
    ap.add_argument('--out', default='proxy-streisand.json')
    ap.add_argument('--max', type=int, default=200, help='лимит нод (0 = без лимита)')
    ap.add_argument('--mode', choices=['ru_direct', 'all_proxy'], default='ru_direct')
    ap.add_argument('--prefix', default='wl-node-')
    ap.add_argument('--nextdns', default='ac3755',
                    help='ID профиля NextDNS (пустая строка — не использовать)')
    ap.add_argument('--parallel-dns', dest='parallel_dns', action='store_true',
                    default=True, help='DNS параллельно, побеждает быстрейший (по умолчанию)')
    ap.add_argument('--sequential-dns', dest='parallel_dns', action='store_false',
                    help='строгий приоритет по порядку: NextDNS → Яндекс → резерв')
    ap.add_argument('--no-fragment', dest='fragment', action='store_false')
    ap.add_argument('--tcp', action='store_true',
                    help='старые имена network=tcp/tcpSettings вместо raw/rawSettings')
    args = ap.parse_args()

    inputs = [x for x in (args.best, args.input) if x]
    proxies = collect(inputs, args.max)
    if not proxies:
        print(f'❌ нет пригодных прокси в {inputs}', file=sys.stderr)
        return 1
    cfg = build(proxies, args)
    if not cfg:
        print('❌ не удалось собрать outbounds', file=sys.stderr)
        return 1
    Path(args.out).write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + '\n',
                              encoding='utf-8')
    types = {}
    for p in proxies:
        types[p['type']] = types.get(p['type'], 0) + 1
    kb = Path(args.out).stat().st_size / 1024
    dns_order = [s for s in cfg['dns']['servers'] if isinstance(s, str) and s != 'fakedns']
    print(f'✅ {args.out}: {len(proxies)} нод {types}, {kb:.0f} КБ, '
          f'режим={args.mode}, фрагмент={"вкл" if args.fragment else "выкл"}, '
          f'network={"tcp" if args.tcp else "raw"}')
    print(f'   DNS: {"параллельно" if args.parallel_dns else "по приоритету"} → '
          + ' → '.join(dns_order[:3]) + ' …')
    return 0


if __name__ == '__main__':
    sys.exit(main())
