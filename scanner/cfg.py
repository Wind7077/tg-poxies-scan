"""Конфиг: YAML + дефолты + переменные окружения."""
import copy
import os
from pathlib import Path

import yaml

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
        'max_embed': 200, 'per_endpoint': 5, 'best': 50,
        'max_attachment_mb': 2, 'core_max': 6000, 'core_batch': 800,
        'core_retry_split': 2,
    },
    'concurrency': {'http': 50, 'ping': 500, 'tls': 100, 'core': 64},
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
        'core_start_wait_s': 45,
        'l3': {
            'enabled': False,
            'telegram': 'https://api.telegram.org/robots.txt',
            'youtube': 'httpv://www.youtube.com/generate_204',
            'timeout_ms': 8000,
            'retries': 2,
            'only_alive': True,
            'require_mode_all': 'both',
            'require_mode_wl': 'off',
            'tag_names': True,
            'min_keep_pct': 15,
            'all_keep_unchecked': True,
            'all_drop_dead': True,
        },
    },
    'cache': {
        'enabled': True, 'dir': '.cache',
        'http_ttl_hours': 6, 'ping_ok_ttl_hours': 12,
        'ping_fail_ttl_hours': 3, 'content_hash': True,
    },
    'telegram': {'api_id': 0, 'api_hash': '', 'session_b64': ''},
    'telethon': {
        'all_channels': True, 'attachments': True,
        'attachment_ext': ['.txt', '.json', '.yaml', '.yml', '.conf', '.list', '.sub', ''],
    },
    'guards': {
        'enabled': True, 'min_parse_rate': 0.6,
        'forbid_empty_wl': True, 'max_all_drop_pct': 70,
    },
    'logging': {
        'debug': True, 'show_live_sources': True,
        'live_sources_top': 0, 'progress_every': 200, 'diag_secrets': False,
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

# YAML 1.1 превращает off/on/yes/no в bool. Возвращаем им строковый смысл.
_BOOL_WORDS = {True: 'on', False: 'off'}
_MODES = {'both', 'any', 'telegram', 'youtube', 'off', 'on'}


class _Obj(dict):
    """Dict с dot-доступом."""

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
    """Глубокая копия: иначе _env_override мутирует _DEFAULTS и портит
    дефолты для всех последующих load() в том же процессе."""
    out = copy.deepcopy(defaults)
    for k, v in overrides.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _norm_mode(v, fallback):
    """require_mode может приехать как bool (YAML off/on) или строка."""
    if isinstance(v, bool):
        v = _BOOL_WORDS[v]
    s = str(v or '').strip().lower()
    if s in ('on', 'yes', 'true'):
        s = 'any'
    return s if s in _MODES else fallback


def _env_override(cfg):
    """Секреты и тюнинг из окружения."""
    tg = cfg.setdefault('telegram', {})
    raw_id = os.getenv('TELEGRAM_API_ID', '').strip()
    if raw_id:
        try:
            tg['api_id'] = int(raw_id)
        except ValueError:
            tg['api_id'] = 0
    if os.getenv('TELEGRAM_API_HASH', '').strip():
        tg['api_hash'] = os.getenv('TELEGRAM_API_HASH').strip()
    if os.getenv('TELEGRAM_SESSION', '').strip():
        tg['session_b64'] = os.getenv('TELEGRAM_SESSION').strip()

    if os.getenv('DEBUG') is not None:
        cfg.setdefault('logging', {})['debug'] = os.getenv('DEBUG') == '1'
    if os.getenv('VERIFY_LEVEL', '').strip():
        try:
            cfg.setdefault('verify', {})['level'] = int(os.getenv('VERIFY_LEVEL'))
        except ValueError:
            pass
    if os.getenv('CORE_MAX', '').strip():
        try:
            cfg.setdefault('limits', {})['core_max'] = int(os.getenv('CORE_MAX'))
        except ValueError:
            pass
    if os.getenv('CORE_BATCH', '').strip():
        try:
            cfg.setdefault('limits', {})['core_batch'] = int(os.getenv('CORE_BATCH'))
        except ValueError:
            pass
    return cfg


def load(path='config.yaml'):
    data = {}
    p = Path(path)
    if p.exists():
        with open(p, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
    merged = _env_override(_deep_merge(_DEFAULTS, data))

    l3 = merged['verify']['l3']
    # обратная совместимость со старым ключом require_mode
    legacy = l3.pop('require_mode', None)
    if legacy is not None:
        l3.setdefault('require_mode_all', legacy)
    l3['require_mode_all'] = _norm_mode(l3.get('require_mode_all'), 'both')
    l3['require_mode_wl'] = _norm_mode(l3.get('require_mode_wl'), 'off')
    return _Obj(merged)
