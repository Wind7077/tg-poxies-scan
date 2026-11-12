"""Классификация «белых»: SNI из белого списка / IP в CIDR / корни в имени (п.3)."""
import ipaddress
import re

_TOKEN_RE = re.compile(r'[^0-9a-zа-яё]+')


def _tokens(p):
    s = ' '.join(str(p.get(k, '')) for k in ('name', 'server', 'sni', 'server-name', 'host')).lower()
    return [t for t in _TOKEN_RE.split(s) if t]


def roots_match(p, cfg):
    roots = [w.lower() for w in str(cfg.whitelist.roots).split() if w]
    return any(t.startswith(r) for t in _tokens(p) for r in roots)


def _host_match(host, domains):
    host = (host or '').lower().rstrip('.')
    if not host:
        return False
    for d in domains:
        d = d.lower().lstrip('.')
        if host == d or host.endswith('.' + d):
            return True
    return False


class Classifier:
    def __init__(self, cfg):
        self.cfg = cfg
        self.domains = list(cfg.whitelist.sni_domains or [])
        self.nets = []
        for c in (cfg.whitelist.cidr or []):
            try:
                self.nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass

    def _ip(self, server):
        try:
            return ipaddress.ip_address(server)
        except ValueError:
            return None

    def classify(self, p):
        """-> (bool, причина). Причина попадает в статистику, не в лог с ссылками."""
        w = self.cfg.whitelist
        if w.require_tls and not p.get('tls'):
            return False, 'no-tls'
        if w.use_sni:
            for key in ('sni', 'server-name', 'host'):
                if _host_match(p.get(key), self.domains):
                    return True, 'sni'
            ws = p.get('ws-opts') or {}
            if _host_match((ws.get('headers') or {}).get('Host'), self.domains):
                return True, 'sni-ws'
        if w.use_cidr and self.nets:
            ip = self._ip(p.get('server', ''))
            if ip and any(ip in n for n in self.nets):
                return True, 'cidr'
        if w.use_roots and roots_match(p, self.cfg):
            return True, 'root'
        return False, ''
