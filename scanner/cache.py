"""ETag/Last-Modified + кэш распарсенных ссылок + пинг-кэш + контент-хэш
   + трекер здоровья источников (давно пустые подписки пропускаются)."""
import hashlib
import json
import time
from pathlib import Path

from . import log

_SOURCE_TTL = 30 * 86400


class Cache:
    def __init__(self, cfg):
        self.cfg = cfg
        self.enabled = bool(cfg.cache.enabled)
        self.dir = Path(cfg.cache.dir)
        self.http = {}
        self.ping = {}
        self.hashes = {}
        self.sources = {}

        sh = getattr(cfg, 'source_health', None)
        self.sh_enabled = bool(self.enabled and sh and getattr(sh, 'enabled', False))
        self.sh_after = max(1, int(getattr(sh, 'after_empty', 10) or 10))
        self.sh_recheck = max(1.0, float(getattr(sh, 'recheck_hours', 24) or 24))

        if self.enabled:
            self.dir.mkdir(parents=True, exist_ok=True)
            self.http = self._read('http.json')
            self.ping = self._read('ping.json')
            self.sources = self._read('sources.json')

    def _read(self, name):
        p = self.dir / name
        if p.exists():
            try:
                return json.loads(p.read_text(encoding='utf-8'))
            except Exception:
                return {}
        return {}

    def save(self):
        if not self.enabled:
            return
        (self.dir / 'http.json').write_text(json.dumps(self.http, ensure_ascii=False), encoding='utf-8')
        (self.dir / 'ping.json').write_text(json.dumps(self.ping), encoding='utf-8')
        cutoff = time.time() - _SOURCE_TTL
        self.sources = {u: e for u, e in self.sources.items()
                        if e.get('ts', 0) >= cutoff}
        (self.dir / 'sources.json').write_text(json.dumps(self.sources, ensure_ascii=False),
                                               encoding='utf-8')
        log.debug(f"💾 кэш: http {len(self.http)}, ping {len(self.ping)}, "
                  f"источников {len(self.sources)}")

    # ---------- HTTP ----------
    def validators(self, url):
        e = self.http.get(url)
        if not e:
            return {}
        h = {}
        if e.get('etag'):
            h['If-None-Match'] = e['etag']
        if e.get('lm'):
            h['If-Modified-Since'] = e['lm']
        return h

    def fresh_uris(self, url):
        """Ссылки из прошлого прогона, если TTL ещё жив (для ответа 304)."""
        e = self.http.get(url)
        if not e:
            return None
        ttl = float(self.cfg.cache.http_ttl_hours) * 3600
        if time.time() - e.get('ts', 0) > ttl:
            return None
        return e.get('uris')

    def put_http(self, url, etag, lm, uris):
        if self.enabled:
            self.http[url] = {'etag': etag or '', 'lm': lm or '',
                              'ts': time.time(), 'uris': uris}

    # ---------- контент-хэш ----------
    def seen_content(self, text):
        """Возвращает уже распарсенный результат для идентичного тела, иначе None."""
        if not (self.enabled and self.cfg.cache.content_hash):
            return None
        h = hashlib.sha256(text.encode('utf-8', 'ignore')).hexdigest()
        return self.hashes.get(h)

    def put_content(self, text, uris):
        if self.enabled and self.cfg.cache.content_hash:
            h = hashlib.sha256(text.encode('utf-8', 'ignore')).hexdigest()
            self.hashes[h] = uris

    # ---------- пинг ----------
    def ping_get(self, host, port):
        e = self.ping.get(f'{host}:{port}')
        if not e:
            return None
        ttl_h = self.cfg.cache.ping_ok_ttl_hours if e.get('ok') else self.cfg.cache.ping_fail_ttl_hours
        if time.time() - e.get('ts', 0) > float(ttl_h) * 3600:
            return None
        return e.get('rtt') if e.get('ok') else None

    def ping_has(self, host, port):
        return self.ping_get(host, port) is not None or f'{host}:{port}' in self.ping and \
            time.time() - self.ping[f'{host}:{port}'].get('ts', 0) <= float(
                self.cfg.cache.ping_ok_ttl_hours if self.ping[f'{host}:{port}'].get('ok')
                else self.cfg.cache.ping_fail_ttl_hours) * 3600

    def ping_put(self, host, port, rtt):
        if self.enabled:
            self.ping[f'{host}:{port}'] = {'ok': rtt is not None, 'rtt': rtt, 'ts': time.time()}

    # ---------- здоровье источников ----------
    def source_skip(self, url):
        """True — источник пуст N прогонов подряд, ждём часа перепроверки."""
        if not self.sh_enabled:
            return False
        e = self.sources.get(url)
        if not e:
            return False
        if int(e.get('empty', 0)) < self.sh_after:
            return False
        return (time.time() - float(e.get('ts', 0))) < self.sh_recheck * 3600

    def source_mark(self, url, empty):
        if not self.sh_enabled:
            return
        e = self.sources.get(url) or {}
        n = int(e.get('empty', 0))
        e['empty'] = n + 1 if empty else 0
        e['ts'] = time.time()
        self.sources[url] = e
