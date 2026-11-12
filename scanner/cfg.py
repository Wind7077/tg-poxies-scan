import yaml
from pathlib import Path


_DEFAULTS = {
    'sources_file': 'sources.txt',
    'outputs': {
        'all_txt': 'proxy-all.txt',
        'all_yaml': 'proxy-all.yaml',
        'wl_txt': 'proxy.txt',
        'wl_yaml': 'proxy.yaml',
        'best_txt': 'proxy-best.txt',
        'best_yaml': 'proxy-best.yaml',
        'wl_base64': 'proxy-base64.txt',
        'issue': 'issue.txt',
        'stats': 'stats.json',
        'live_sources': 'sources-live.txt',
    },
    'windows': {'wl_days': 50, 'all_days': 10},
    'limits': {
        'tme_pages': 10, 'tme_sub_pages': 2, 'telethon_limit': 1000,
        'max_embed': 200, 'per_endpoint': 5, 'best': 50, 'max_attachment_mb': 2,
    },
    'concurrency': {'http': 50, 'ping': 500, 'tls': 100, 'core': 32},
    'timeouts': {
        'http_total': 12, 'http_connect': 7, 'long_total': 30,
        'ping': 2.0, 'tls': 3.0, 'core_delay_ms': 5000,
    },
    'protocols': {
        'all': ['vless', 'vmess', 'ss', 'trojan', 'hysteria2', 'tuic'],
        'wl': ['vless'],
    },
    'verify': {
        'level': 2,
        'core_api': 'https://api.github.com/repos/MetaCubeX/mihomo/releases/latest',
        'controller': '127.0.0.1:19090',
        'mixed_port': 17890,
        'test_url': 'http://www.gstatic.com/generate_204',
        'geo_top': 0,
        'geo_url': 'https://api.ipify.org?format=json',
        'l3': {
            'enabled': False,
            'telegram': 'https://api.telegram.org/robots.txt',
            'youtube': 'https://www.youtube.com/generate_204',
            'timeout_ms': 12000,
            'retries': 2,
            'only_alive': True,
            'require_mode': 'telegram',
            'tag_names': True,
        },
    },
    'cache': {
        'enabled': True, 'dir': '.cache',
        'http_ttl_hours': 6, 'ping_ok_ttl_hours': 12,
        'ping_fail_ttl_hours': 3, 'content_hash': True,
    },
    'telethon': {'all_channels': True, 'attachments': True},
    'guards': {
        'enabled': True, 'min_parse_rate': 0.6,
        'forbid_empty_wl': True, 'max_all_drop_pct': 70,
    },
    'logging': {
        'debug': True, 'show_live_sources': True,
        'live_sources_top': 0, 'progress_every': 200,
    },
    'problem_domains': [],
    'blacklist_domains': [],
    'junk_domains': [],
    'whitelist': {
        'roots': '',
        'use_roots': True, 'use_sni': True, 'use_cidr': True,
        'require_tls': False, 'sni_domains': [], 'cidr': [],
    },
}


class _Obj(dict):
    """Dict с dot-доступом и дефолтами из _DEFAULTS."""
    def __getattr__(self, item):
        try:
            v = self[item]
        except KeyError:
            raise AttributeError(item)
        if isinstance(v, dict) and not isinstance(v, _Obj):
            v = _Obj(v)
            self[item] = v
        return v

    def __setattr__(self, key, value):
        self[key] = value


def _deep_merge(defaults, overrides):
    out = dict(defaults)
    for k, v in overrides.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path='config.yaml'):
    data = {}
    p = Path(path)
    if p.exists():
        with open(p, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
    merged = _deep_merge(_DEFAULTS, data)
    return _Obj(merged)
