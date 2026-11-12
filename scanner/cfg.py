import os
from pathlib import Path

import yaml


class Dot(dict):
    """Доступ к настройкам через точку: cfg.verify.level"""

    def __getattr__(self, item):
        try:
            v = self[item]
        except KeyError:
            raise AttributeError(item)
        return Dot(v) if isinstance(v, dict) else v


def load(path='config.yaml'):
    raw = {}
    p = Path(path)
    if p.exists():
        raw = yaml.safe_load(p.read_text(encoding='utf-8')) or {}
    cfg = Dot(raw)
    cfg['telegram'] = {
        'api_id': int(os.getenv('TELEGRAM_API_ID', '0') or 0),
        'api_hash': os.getenv('TELEGRAM_API_HASH', ''),
        'session_b64': os.getenv('TELEGRAM_SESSION', ''),
    }
    if os.getenv('DEBUG') is not None:
        cfg.setdefault('logging', {})['debug'] = os.getenv('DEBUG') == '1'
    if os.getenv('VERIFY_LEVEL'):
        cfg.setdefault('verify', {})['level'] = int(os.getenv('VERIFY_LEVEL'))
    return cfg
