"""L0 TCP → L1 TLS → L2 ядро (delay) → L3 сервисы (Telegram/YouTube).

Ядро запускается ПАЧКАМИ: один процесс на 6000 конфигов не поднимается,
и один битый конфиг убивал бы всю проверку. Пачка изолирует проблему.
"""
import asyncio
import gzip
import os
import platform
import shutil
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

import aiohttp
import yaml

from . import log
from .net import ping


async def l0_tcp(endpoints, cfg, cache, sem):
    """-> {(host, port): rtt|None}. Кэш с TTL, каждый endpoint один раз."""
    out, todo = {}, []
    for hp in endpoints:
        e = cache.ping.get(f'{hp[0]}:{hp[1]}') if cache else None
        fresh = False
        if e:
            ttl = float(cfg.cache.ping_ok_ttl_hours if e.get('ok')
                        else cfg.cache.ping_fail_ttl_hours)
            fresh = time.time() - e.get('ts', 0) <= ttl * 3600
        if fresh:
            out[hp] = e.get('rtt') if e.get('ok') else None
        else:
            todo.append(hp)
    log.debug(f'🌐 L0: всего {len(endpoints)}, из кэша {len(out)}, пингуем {len(todo)}')

    async def one(hp):
        t0 = time.perf_counter()
        ok = await ping(hp[0], hp[1], sem, float(cfg.timeouts.ping))
        rtt = (time.perf_counter() - t0) if ok else None
        if cache:
            cache.ping_put(hp[0], hp[1], rtt)
        return hp, rtt

    if todo:
        for hp, rtt in await asyncio.gather(*(one(hp) for hp in todo)):
            out[hp] = rtt
    return out


async def l1_tls(items, cfg):
    """items: [(key, host, port, sni)] -> {key: bool}. Только TLS-конфиги."""
    if not items:
        return {}
    sem = asyncio.Semaphore(int(cfg.concurrency.tls))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    async def one(key, host, port, sni):
        async with sem:
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(host, int(port), ssl=ctx,
                                            server_hostname=sni or None),
                    timeout=float(cfg.timeouts.tls))
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                return key, True
            except asyncio.CancelledError:
                raise
            except Exception:
                return key, False

    res = await asyncio.gather(*(one(*x) for x in items))
    ok = sum(1 for _, v in res if v)
    log.debug(f'🔐 L1 TLS: проверено {len(items)}, рукопожатие прошло {ok}')
    return dict(res)


def _core_asset_prefix():
    machine = (platform.machine() or '').lower()
    arch = 'arm64' if machine in ('aarch64', 'arm64') else 'amd64'
    return f'mihomo-linux-{arch}'


def _binary_ok(path):
    """Кэш мог принести битый/обрезанный бинарник."""
    try:
        r = subprocess.run([str(path), '-v'], capture_output=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False


async def _ensure_core(cfg, session):
    """Скачивает mihomo. Возвращает путь или None (мягкий откат на L1)."""
    bindir = Path(cfg.cache.dir) / 'bin'
    bindir.mkdir(parents=True, exist_ok=True)
    binary = bindir / 'mihomo'
    if binary.exists():
        if os.access(binary, os.X_OK) and _binary_ok(binary):
            return str(binary)
        log.debug('⚠️ L2: сохранённый mihomo не запускается — перекачиваем')
        try:
            binary.unlink()
        except OSError:
            return None
    prefix = _core_asset_prefix()
    try:
        async with session.get(cfg.verify.core_api,
                               headers={'Accept': 'application/vnd.github+json'},
                               timeout=aiohttp.ClientTimeout(total=30)) as r:
            if r.status != 200:
                log.debug(f'⚠️ L2: релиз mihomo недоступен ({r.status})')
                return None
            data = await r.json()
        asset = None
        for a in data.get('assets', []):
            n = a.get('name', '')
            if n.startswith(prefix) and n.endswith('.gz') and 'compatible' not in n:
                asset = a
                break
        if not asset:
            log.debug(f'⚠️ L2: бинарник {prefix} не найден в релизе')
            return None
        async with session.get(asset['browser_download_url'],
                               timeout=aiohttp.ClientTimeout(total=180)) as r:
            if r.status != 200:
                return None
            blob = await r.read()
        binary.write_bytes(gzip.decompress(blob))
        binary.chmod(0o755)
        if not _binary_ok(binary):
            log.debug('⚠️ L2: скачанный mihomo не запускается')
            return None
        log.debug(f'⬇️ L2: mihomo скачан ({prefix})')
        return str(binary)
    except Exception as e:
        log.debug(f'⚠️ L2: не удалось получить ядро ({type(e).__name__})')
        return None


def _core_ok(p):
    """Минимальная проверка: не отправляем в ядро заведомо битые конфиги."""
    t = p.get('type')
    if t not in ('vless', 'vmess', 'ss', 'trojan', 'hysteria2', 'tuic'):
        return False
    if not p.get('server') or not p.get('port'):
        return False
    if t in ('vless', 'vmess', 'tuic') and not p.get('uuid'):
        return False
    if t in ('ss', 'trojan', 'hysteria2') and not p.get('password'):
        return False
    if t == 'ss' and not p.get('cipher'):
        return False
    if t == 'tuic' and not p.get('password'):
        return False
    return True


def _ctrl_parts(cfg):
    s = str(cfg.verify.controller)
    if ':' in s:
        host, port = s.rsplit(':', 1)
        try:
            return host, int(port)
        except ValueError:
            pass
    return '127.0.0.1', 19090


async def _core_batch(batch, cfg, binary, mixed_port, ctrl_host, ctrl_port):
    """Один запуск mihomo на пачку. -> (delays, geo, tg, yt, started)"""
    tmp = Path(tempfile.mkdtemp(prefix='mihomo-'))
    conf = {
        'mixed-port': int(mixed_port),
        'external-controller': f'{ctrl_host}:{ctrl_port}',
        'mode': 'global',
        'log-level': 'error',
        'ipv6': False,
        'proxies': [p for _, p in batch],
        'proxy-groups': [{'name': 'GLOBAL', 'type': 'select',
                          'proxies': [n for n, _ in batch]}],
        'rules': ['MATCH,GLOBAL'],
    }
    (tmp / 'config.yaml').write_text(
        yaml.dump(conf, allow_unicode=True, sort_keys=False), encoding='utf-8')

    base = f'http://{ctrl_host}:{ctrl_port}'
    delays, geo, l3_tg, l3_yt = {}, {}, {}, {}
    proc = None
    started = False
    err_path = tmp / 'stderr.log'
    try:
        errf = open(err_path, 'wb')
        try:
            proc = subprocess.Popen(
                [binary, '-d', str(tmp), '-f', str(tmp / 'config.yaml')],
                stdout=subprocess.DEVNULL, stderr=errf)
        finally:
            errf.close()   # дочерний процесс держит свой fd

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=40)) as api:
            wait_s = float(getattr(cfg.verify, 'core_start_wait_s', 45))
            deadline = time.time() + wait_s
            while time.time() < deadline:
                if proc.poll() is not None:      # ядро уже упало — не ждём
                    break
                try:
                    async with api.get(base + '/version') as r:
                        if r.status == 200:
                            started = True
                            break
                except Exception:
                    pass
                await asyncio.sleep(0.3)

            if not started:
                tail = ''
                try:
                    tail = err_path.read_text(encoding='utf-8', errors='ignore')
                    tail = tail.strip().replace('\n', ' | ')[-400:]
                except Exception:
                    pass
                log.info(f'⚠️ L2: ядро не поднялось (пачка {len(batch)}, '
                         f'exit={proc.poll()}) {tail}')
                return delays, geo, l3_tg, l3_yt, False

            sem = asyncio.Semaphore(int(cfg.concurrency.core))
            test_url = cfg.verify.test_url
            tmo = int(cfg.timeouts.core_delay_ms)

            async def _delay(name, url, timeout_ms):
                u = f"{base}/proxies/{quote(name, safe='')}/delay"
                async with api.get(u, params={'url': url, 'timeout': str(timeout_ms)}) as r:
                    body = await r.json(content_type=None)
                    d = body.get('delay') if isinstance(body, dict) else None
                    return int(d) if isinstance(d, int) and d > 0 else None

            # ---------- L2 ----------
            async def delay(name):
                async with sem:
                    try:
                        return name, await _delay(name, test_url, tmo)
                    except Exception:
                        return name, None

            t0 = time.time()
            for name, d in await asyncio.gather(*(delay(n) for n, _ in batch)):
                delays[name] = d
            ok = sum(1 for v in delays.values() if v)
            log.debug(f'[L2] пачка {len(batch)}: работают {ok} ({time.time()-t0:.0f}s)')

            # ---------- L3 ----------
            l3cfg = getattr(cfg.verify, 'l3', None)
            if l3cfg and getattr(l3cfg, 'enabled', False):
                tg_url = getattr(l3cfg, 'telegram', '') or ''
                yt_url = getattr(l3cfg, 'youtube', '') or ''
                l3_tmo = int(getattr(l3cfg, 'timeout_ms', 8000))
                l3_retries = max(1, int(getattr(l3cfg, 'retries', 2)))
                only_alive = bool(getattr(l3cfg, 'only_alive', True))
                targets = [n for n, _ in batch if delays.get(n) or not only_alive]

                async def probe_service(name, url):
                    for attempt in range(l3_retries):
                        try:
                            if await _delay(name, url, l3_tmo) is not None:
                                return True
                        except Exception:
                            pass
                        if attempt < l3_retries - 1:
                            await asyncio.sleep(0.4)
                    return False

                async def l3_check(name):
                    async with sem:
                        tg = await probe_service(name, tg_url) if tg_url else None
                        yt = await probe_service(name, yt_url) if yt_url else None
                        return name, tg, yt

                if targets and (tg_url or yt_url):
                    for name, tg, yt in await asyncio.gather(*(l3_check(n) for n in targets)):
                        if tg is not None:
                            l3_tg[name] = tg
                        if yt is not None:
                            l3_yt[name] = yt

            # ---------- Geo (опционально) ----------
            top = int(cfg.verify.geo_top or 0)
            if top > 0:
                alive = sorted([(n, d) for n, d in delays.items() if d],
                               key=lambda x: x[1])[:top]
                proxy = f'http://127.0.0.1:{int(mixed_port)}'
                for name, _d in alive:
                    try:
                        async with api.put(base + '/proxies/GLOBAL', json={'name': name}):
                            pass
                        async with api.get(cfg.verify.geo_url, proxy=proxy,
                                           timeout=aiohttp.ClientTimeout(total=12)) as r:
                            j = await r.json(content_type=None)
                            ip = j.get('ip')
                        if ip:
                            async with api.get(f'http://ip-api.com/json/{ip}?fields=countryCode',
                                               timeout=aiohttp.ClientTimeout(total=10)) as r:
                                j2 = await r.json(content_type=None)
                                if j2.get('countryCode'):
                                    geo[name] = j2['countryCode']
                    except Exception:
                        continue
    except Exception as e:
        log.debug(f'⚠️ L2/L3: сбой пачки ({type(e).__name__})')
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        shutil.rmtree(tmp, ignore_errors=True)
    return delays, geo, l3_tg, l3_yt, started


async def l2_core(named, cfg, session):
    """named: [(name, clash_dict)] -> (delays, geo, l3_tg, l3_yt).

    Проверка идёт пачками по limits.core_batch. Пачка, которая не смогла
    стартовать, пропускается — остальные продолжают работу.
    """
    empty = ({}, {}, {}, {})
    if not named:
        return empty
    binary = await _ensure_core(cfg, session)
    if not binary:
        return empty

    good = [(n, p) for n, p in named if _core_ok(p)]
    skipped = len(named) - len(good)
    if skipped:
        log.debug(f'🧹 L2: отброшено непригодных для ядра {skipped}')
    if not good:
        return empty

    size = max(50, int(getattr(cfg.limits, 'core_batch', 800) or 800))
    batches = [good[i:i + size] for i in range(0, len(good), size)]
    ctrl_host, ctrl_port = _ctrl_parts(cfg)
    base_mixed = int(cfg.verify.mixed_port)

    delays, geo, l3_tg, l3_yt = {}, {}, {}, {}
    ok_batches = 0
    t0 = time.time()
    for i, batch in enumerate(batches):
        d, g, tg, yt, started = await _core_batch(
            batch, cfg, binary, base_mixed + i, ctrl_host, ctrl_port + i)
        if started:
            ok_batches += 1
        delays.update(d)
        geo.update(g)
        l3_tg.update(tg)
        l3_yt.update(yt)

    alive = sum(1 for v in delays.values() if v)
    log.info(f'[L2] через ядро проверено {len(delays)}/{len(good)}, '
             f'реально работают {alive} '
             f'(пачек {ok_batches}/{len(batches)}, {time.time()-t0:.0f}s)')
    if l3_tg or l3_yt:
        tg_ok = sum(1 for v in l3_tg.values() if v)
        yt_ok = sum(1 for v in l3_yt.values() if v)
        both = sum(1 for n in l3_tg if l3_tg.get(n) and l3_yt.get(n))
        log.info(f'[L3] проверено {len(l3_tg)} → TG {tg_ok} | YT {yt_ok} | оба {both}')
    return delays, geo, l3_tg, l3_yt
