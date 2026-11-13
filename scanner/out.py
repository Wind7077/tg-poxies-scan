import base64
import json
import re
from pathlib import Path

import yaml

from . import log
from .extract import ISSUE_URLS, clean_url, now_utc, split_issues, valid_issue

_GO_NUM = re.compile(r'^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$')
_WORDS = {'y', 'n', 'yes', 'no', 'on', 'off', 'true', 'false', 'null', '~'}


class Dumper(yaml.SafeDumper):
    pass


def _str_rep(dumper, data):
    if _GO_NUM.match(data) or data.lower() in _WORDS:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


Dumper.add_representer(str, _str_rep)


def unique_names(proxies):
    used, renamed = {}, 0
    for p in proxies:
        name = (p.get('name') or '').strip() or f"{p.get('type')}-{p.get('server')}:{p.get('port')}"
        if name in used:
            used[name] += 1
            name = f'{name} #{used[name]}'
            renamed += 1
        else:
            used[name] = 1
        p['name'] = name
    if renamed:
        log.debug(f'🏷️ Переименовано дубликатов имён: {renamed}')
    return proxies


def _old_body(path):
    p = Path(path)
    if not p.exists():
        return None
    lines = p.read_text(encoding='utf-8').splitlines()
    while lines and lines[0].startswith('#'):
        lines.pop(0)
    return '\n'.join(lines)


def prev_count(path):
    p = Path(path)
    if not p.exists():
        return 0
    for line in p.read_text(encoding='utf-8').splitlines()[:5]:
        m = re.match(r'#\s*Живых:\s*(\d+)', line)
        if m:
            return int(m.group(1))
    return 0


def write_txt(path, uris, count):
    body = '\n'.join(uris)
    if _old_body(path) == body:
        log.debug(f'📄 {path}: без изменений')
        return False
    ts = now_utc().strftime('%Y-%m-%d %H:%M:%S UTC')
    Path(path).write_text(f'# Обновлено: {ts}\n# Живых: {count}\n#\n{body}\n', encoding='utf-8')
    return True


def clash_doc(proxies):
    names = [p['name'] for p in proxies] or ['DIRECT']
    return {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'Rule', 'log-level': 'info',
        'external-controller': '127.0.0.1:9090', 'proxies': proxies,
        'proxy-groups': [
            {'name': '♻️ Auto', 'type': 'url-test', 'proxies': names,
             'url': 'http://www.gstatic.com/generate_204', 'interval': 300, 'tolerance': 50},
            {'name': '🚀 Proxy', 'type': 'select', 'proxies': ['♻️ Auto'] + names},
        ],
        'rules': ['MATCH,🚀 Proxy'],
    }


def write_yaml(path, proxies):
    body = yaml.dump(clash_doc(proxies), Dumper=Dumper, sort_keys=False,
                     allow_unicode=True).rstrip('\n')
    p = Path(path)
    if p.exists() and p.read_text(encoding='utf-8').rstrip('\n') == body:
        log.debug(f'📄 {path}: без изменений')
        return False
    p.write_text(body + '\n', encoding='utf-8')
    return True


def write_base64(path, uris):
    body = base64.b64encode('\n'.join(uris).encode('utf-8')).decode('ascii')
    p = Path(path)
    if p.exists() and p.read_text(encoding='utf-8').strip() == body:
        return False
    p.write_text(body + '\n', encoding='utf-8')
    return True


def write_issue(path):
    if not ISSUE_URLS:
        return
    clean = set()
    for u in ISSUE_URLS:
        for s in split_issues(u):
            c = clean_url(s)
            if valid_issue(c):
                clean.add(c)
    if not clean:
        return
    rows = sorted(clean)
    write_txt(path, rows, len(rows))
    log.debug(f'📄 {path}: {len(rows)} валидных (из {len(ISSUE_URLS)} сырых)')


def write_live_sources(path, wl_counter, all_counter):
    rows = sorted(set(wl_counter) | set(all_counter))
    lines = [f'# Источники, давшие живые прокси. Обновлено {now_utc():%Y-%m-%d %H:%M:%S UTC}',
             f'# Всего: {len(rows)}', '']
    for s in rows:
        lines.append(f'{wl_counter.get(s, 0):>5} WL {all_counter.get(s, 0):>5} ALL  {s}')
    Path(path).write_text('\n'.join(lines) + '\n', encoding='utf-8')


def write_stats(path, stats):
    Path(path).write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding='utf-8')


def guard(cfg, stats, prev):
    """Circuit breaker: не публикуем сломанный результат."""
    g = cfg.guards
    if not g.enabled:
        return []
    problems = []
    parsed = int(stats.get('parsed', 0))
    # Знаменатель — ЧИСЛО ПОПЫТОК ПАРСИНГА, а не stats['candidates']:
    # тот считается ДО дедупа и содержит одну и ту же ссылку из каждого
    # источника (52 384 против 24 369 уникальных), из-за чего здоровый
    # прогон давал 0.45 и блокировал публикацию.
    # Цепочка: parse_fails (точнее всего) → reps → candidates.
    fails = stats.get('parse_fails')
    if fails is not None:
        attempts = parsed + sum(int(v) for v in (fails or {}).values())
    else:
        attempts = int(stats.get('reps') or stats.get('candidates') or 0)
    if not attempts:
        attempts = parsed
    rate = (parsed / attempts) if attempts else 1.0
    stats['parse_attempts'] = attempts
    stats['parse_rate'] = round(rate, 4)
    if attempts and rate < float(g.min_parse_rate):
        problems.append(f'parse_rate {rate:.2f} ({parsed}/{attempts}) < {g.min_parse_rate}')
    if g.forbid_empty_wl and stats.get('wl', 0) == 0 and prev.get('wl', 0) > 0:
        problems.append(f"WL=0 при прошлом {prev['wl']}")
    if prev.get('all', 0) > 0:
        drop = 100 * (1 - stats.get('all', 0) / prev['all'])
        if drop > float(g.max_all_drop_pct):
            problems.append(f'ALL упал на {drop:.0f}%')
    return problems
