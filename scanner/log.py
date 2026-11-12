"""Лог без источников. Полные ссылки печатаются только для тех, что дали живые прокси."""

STATS = {'http_ok': 0, 'http_fail': 0, 'http_304': 0, 'bytes': 0, 'sub_links': 0}

_cfg = None


def init(cfg):
    global _cfg
    _cfg = cfg


def _dbg():
    return bool(_cfg is None or _cfg.logging.debug)


def debug(msg):
    if _dbg():
        print(f"[DEBUG] {msg}", flush=True)


def info(msg):
    print(msg, flush=True)


def fmt_bytes(n):
    return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{n / 1024:.1f} KB"


def progress():
    every = int(_cfg.logging.progress_every or 0) if _cfg else 200
    total = STATS['http_ok'] + STATS['http_fail'] + STATS['http_304']
    if every and _dbg() and total and total % every == 0:
        print(f"[HTTP] {total} запросов (ok {STATS['http_ok']} / 304 {STATS['http_304']} "
              f"/ fail {STATS['http_fail']}), скачано {fmt_bytes(STATS['bytes'])}", flush=True)


def scheme_hist(uris, top=8):
    h = {}
    for u in uris:
        s = u.split('://', 1)[0].lower()[:12]
        h[s] = h.get(s, 0) + 1
    rows = sorted(h.items(), key=lambda kv: -kv[1])[:top]
    return '{' + ', '.join(f'{k}: {v}' for k, v in rows) + '}'


def hist(d, top=8):
    rows = sorted(d.items(), key=lambda kv: -kv[1])[:top]
    return '{' + ', '.join(f'{k}: {v}' for k, v in rows) + '}'


def live_sources(label, counter):
    if not _cfg or not _cfg.logging.show_live_sources:
        return
    if not counter:
        print(f"[ИСТОЧНИКИ {label}] нет источников с живыми прокси", flush=True)
        return
    rows = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    top = int(_cfg.logging.live_sources_top or 0)
    shown = rows[:top] if top > 0 else rows
    print(f"[ИСТОЧНИКИ {label}] {len(counter)} источников дали живые прокси "
          f"(показано {len(shown)}):", flush=True)
    for i, (src, n) in enumerate(shown, 1):
        print(f"  {i}. {n:>5}  {src}", flush=True)
