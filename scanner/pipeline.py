import asyncio
import time
from datetime import timedelta
from pathlib import Path

from . import log
from .cache import Cache
from .cfg import load
from .dedup import dedupe, split_uri
from .extract import TME_RE, clean_url, now_utc, sub_key
from .net import make_session
from .out import (guard, prev_count, unique_names, write_base64, write_issue,
                  write_live_sources, write_stats, write_txt, write_yaml)
from .parse import fail_reason, parse, sanitize, validate
from .sources import classify_sources, subscription, telethon_channels, web_channel
from .verify import l0_tcp, l1_tls, l2_core
from .wl import Classifier


async def run(config_path='config.yaml'):
    cfg = load(config_path)
    log.init(cfg)
    start = time.time()
    o = cfg.outputs

    sf = Path(cfg.sources_file)
    if not sf.exists():
        log.info('sources.txt не найден!')
        return 1
    lines = [l.strip() for l in sf.read_text(encoding='utf-8').splitlines()
             if l.strip() and not l.startswith('#')]

    cache = Cache(cfg)
    cutoff_wl = now_utc() - timedelta(days=int(cfg.windows.wl_days))
    cutoff_all = now_utc() - timedelta(days=int(cfg.windows.all_days))

    web, embed, tg, subs = classify_sources(lines, cfg)
    use_tg = bool(cfg.telethon.all_channels) and cfg.telegram.session_b64
    if use_tg:
        tg = tg + web + embed
        web, embed = [], []
    log.info(f'Каналов web: {len(web)}, сообщений: {len(embed)}, Telethon: {len(tg)}, '
             f'подписок: {len(subs)}')

    items, visited = [], set()
    http_sem = asyncio.Semaphore(int(cfg.concurrency.http))
    ping_sem = asyncio.Semaphore(int(cfg.concurrency.ping))

    async with make_session(cfg) as session:
        if web or embed:
            jobs = [(u, web_channel(session, http_sem, u, cutoff_wl, cfg.limits.tme_pages, cfg))
                    for u in web]
            jobs += [(u, _one_embed(session, http_sem, u, cutoff_wl, cfg)) for u in embed]
            results = await asyncio.gather(*(c for _, c in jobs))
            for (src, _), (p, urls) in zip(jobs, results):
                items.extend((u, dt, src) for u, dt in p)
                subs.update(clean_url(x) for x in urls)
            for w in web:
                visited.add(sub_key(w))
            log.debug(f'Каналы: ссылок {len(items)}, найдено подписок {len(subs)}')

        if tg:
            p, urls = await telethon_channels(tg, cutoff_wl, cfg)
            items.extend(p)
            subs.update(clean_url(x) for x in urls)

        known = set()
        for src in web + embed + tg:
            m = TME_RE.match(src)
            if m:
                known.add(m.group(1).lower())
        if known:
            n0 = len(subs)
            subs = {u for u in subs
                    if not ((m := TME_RE.match(u)) and m.group(1).lower() in known)}
            log.debug(f'⏭️ Пропущено ссылок на уже прочитанные каналы: {n0 - len(subs)}')

        if subs:
            rows = sorted({u.rstrip('/') for u in subs if u})
            cap = int(cfg.limits.max_embed)
            if cap > 0:
                embeds = [u for u in rows if (m := TME_RE.match(u)) and m.group(2)]
                if len(embeds) > cap:
                    drop = set(embeds[cap:])
                    rows = [u for u in rows if u not in drop]
                    log.debug(f'⏭️ Embed-лимит: пропущено {len(drop)} чужих сообщений')
            log.info(f'[{time.time()-start:.1f}s] Подписок в очереди: {len(rows)}')
            for r in await asyncio.gather(*(subscription(u, session, http_sem, visited,
                                                         cutoff_wl, cfg, cache) for u in rows)):
                items.extend(r)

        # дедуп по URI: свежая дата + все источники
        merged = {}
        for uri, dt, src in items:
            e = merged.get(uri)
            if e is None:
                merged[uri] = [dt, {src} if src else set()]
            else:
                if dt > e[0]:
                    e[0] = dt
                if src:
                    e[1].add(src)
        log.info(f'[{time.time()-start:.1f}s] Сырых прокси: {len(merged)}')

        # ---------- ОДИН проход: расклейка → дедуп → парсинг ----------
        fresh, origin = [], {}
        glued = 0
        for uri in merged:
            variants, tails = split_uri(uri)
            cand = variants[0]
            fresh.append(cand)
            origin.setdefault(cand, set()).add(uri)
            if len(variants) > 1 or tails:
                glued += 1
            for t in tails:
                fresh.append(t)
                origin.setdefault(t, set()).add(uri)

        reps, members = dedupe(fresh, cfg)
        log.debug(f'📦 кандидатов {len(fresh)} {log.scheme_hist(fresh)} → после дедупа {len(reps)}')
        if glued:
            log.debug(f'🧩 расклеено ссылок {glued}')

        parsed, prov, dates, fails, rescued = {}, {}, {}, {}, 0
        for rep in reps:
            if rep.lower().startswith('happ://'):
                continue
            p = parse(rep)
            used = rep
            if p is None and len(split_uri(rep)[0]) > 1:
                p = parse(split_uri(rep)[-1])
                if p is not None:
                    used = split_uri(rep)[-1]
                    rescued += 1
            if p and p.get('server') and p.get('port'):
                p = sanitize(p)
                parsed[used] = p
                srcs, dts = set(), []
                for m in members.get(rep, [rep]):
                    for orig in origin.get(m, (m,)):
                        e = merged.get(orig)
                        if e:
                            srcs |= e[1]
                            dts.append(e[0])
                prov[used] = srcs
                dates[used] = max(dts) if dts else now_utc()
            else:
                r = fail_reason(rep)
                fails[r] = fails.get(r, 0) + 1

        if rescued:
            log.debug(f'🛟 спасено фолбэком на оригинал {rescued}')
        if fails:
            log.debug(f'⚠️ не распарсено {sum(fails.values())} {log.hist(fails)}')
        log.debug(f'✅ распарсено {len(parsed)} {log.scheme_hist(parsed)}')

        # ---------- L0 ----------
        endpoints = {(p['server'], p['port']) for p in parsed.values()}
        ping_map = await l0_tcp(endpoints, cfg, cache, ping_sem)
        alive = [(u, p) for u, p in parsed.items()
                 if ping_map.get((p['server'], p['port'])) is not None]
        alive.sort(key=lambda up: (up[1]['type'], up[1]['server'], up[1]['port'], up[0]))
        log.info(f'[L0] живых endpoint-пар: {len(alive)}')

        # ---------- WL-кандидаты ----------
        clf = Classifier(cfg)
        wl_proto = set(cfg.protocols.wl)
        wl_items, wl_reasons = [], {}
        for u, p in alive:
            if p.get('type') not in wl_proto:
                continue
            ok, why = clf.classify(p)
            if ok:
                wl_items.append((u, p))
                wl_reasons[why] = wl_reasons.get(why, 0) + 1
        log.debug(f'🎯 WL до проверки: {len(wl_items)} {log.hist(wl_reasons)}')

        # ---------- L1 / L2 ----------
        level = int(cfg.verify.level)
        delays, geo = {}, {}
        if level >= 1 and wl_items:
            tls_jobs = []
            for u, p in wl_items:
                if p.get('tls') and p.get('type') in ('vless', 'trojan', 'vmess'):
                    sni = p.get('server-name') or p.get('sni') or ''
                    tls_jobs.append((u, p['server'], p['port'], sni))
            if tls_jobs:
                tls_ok = await l1_tls(tls_jobs, cfg)
                wl_items = [(u, p) for u, p in wl_items
                            if u not in tls_ok or tls_ok[u]]
                log.debug(f'🔐 после L1 осталось {len(wl_items)}')

        if level >= 2 and wl_items:
            named = []
            for i, (u, p) in enumerate(wl_items):
                q = dict(p)
                q['name'] = f'p{i}'
                named.append((f'p{i}', q))
            d, g = await l2_core(named, cfg, session)
            if d:
                idx = {f'p{i}': u for i, (u, _) in enumerate(wl_items)}
                delays = {idx[k]: v for k, v in d.items() if k in idx}
                geo = {idx[k]: v for k, v in g.items() if k in idx}
                wl_items = [(u, p) for u, p in wl_items if delays.get(u)]
                log.info(f'[L2] подтверждено рабочих: {len(wl_items)}')
            else:
                log.debug('⚠️ L2 недоступен — остаёмся на L1')

        cache.save()

    # ---------- сборка списков ----------
    all_proto = set(cfg.protocols.all)
    all_txt, all_clash, all_src = [], [], {}
    for u, p in alive:
        if dates.get(u, now_utc()) < cutoff_all:
            continue
        keep_yaml = p.get('type') in all_proto and validate(p)[0]
        all_txt.append(u)
        if keep_yaml:
            all_clash.append(dict(p))
        for s in prov.get(u, ()):
            all_src[s] = all_src.get(s, 0) + 1

    # WL: сохраняем пары (uri, clash_dict) для корректного best
    wl_pairs = []          # [(uri, clash_dict)]
    wl_txt, wl_src = [], {}
    for u, p in wl_items:
        if not validate(p)[0]:
            continue
        q = dict(p)
        if u in geo:
            q['name'] = f"{geo[u]} · {q.get('name', '')}".strip(' ·')
        if u in delays and delays[u]:
            q['name'] = f"{q.get('name', '')} · {delays[u]}ms".strip(' ·')
        wl_txt.append(u)
        wl_pairs.append((u, q))
        for s in prov.get(u, ()):
            wl_src[s] = wl_src.get(s, 0) + 1

    all_clash = unique_names(all_clash)
    wl_clash = unique_names([p for _, p in wl_pairs])
    all_txt = sorted(set(all_txt))
    wl_txt = sorted(set(wl_txt))

    # Best: сортируем по задержке из wl_pairs (НЕ из раздельных списков)
    best = sorted(wl_pairs, key=lambda up: delays.get(up[0]) or 10 ** 9)[:int(cfg.limits.best)]
    best_txt = [u for u, _ in best]
    best_clash = [p for _, p in best]

    stats = {
        'ts': now_utc().isoformat(),
        'raw': len(merged), 'candidates': len(fresh), 'reps': len(reps),
        'parsed': len(parsed), 'parse_fails': fails,
        'alive_l0': len(alive), 'wl_l1l2': len(wl_items),
        'all': len(all_txt), 'all_yaml': len(all_clash),
        'wl': len(wl_txt), 'wl_yaml': len(wl_clash),
        'wl_reasons': wl_reasons, 'verify_level': level,
        'http': dict(log.STATS), 'seconds': round(time.time() - start, 1),
        'sources_wl': len(wl_src), 'sources_all': len(all_src),
    }

    prev = {'wl': prev_count(o.wl_txt), 'all': prev_count(o.all_txt)}
    problems = guard(cfg, stats, prev)
    stats['guard_problems'] = problems
    log.debug(f'🛡️ parse_rate {stats.get("parse_rate")} '
              f'({stats.get("parse_attempts")} попыток, дедуп {len(fresh)}→{len(reps)}), '
              f'prev ALL={prev["all"]} WL={prev["wl"]}')
    write_stats(o.stats, stats)

    log.debug(f'📊 ALL: txt={len(all_txt)} yaml={len(all_clash)} | '
              f'WL: txt={len(wl_txt)} yaml={len(wl_clash)}')

    if problems:
        log.info('🛑 CIRCUIT BREAKER: ' + '; '.join(problems))
        log.info('🛑 Файлы НЕ перезаписаны — остались прошлые хорошие списки.')
        log.live_sources('WL', wl_src)
        return 1

    write_txt(o.all_txt, all_txt, len(all_txt))
    write_yaml(o.all_yaml, all_clash)
    write_txt(o.wl_txt, wl_txt, len(wl_txt))
    write_yaml(o.wl_yaml, wl_clash)
    write_txt(o.best_txt, best_txt, len(best_txt))
    write_yaml(o.best_yaml, best_clash)
    write_base64(o.wl_base64, wl_txt)
    write_issue(o.issue)
    write_live_sources(o.live_sources, wl_src, all_src)

    log.live_sources('WL', wl_src)
    log.live_sources('ALL', all_src)
    log.info(f'✅ Готово за {time.time()-start:.1f} сек!')
    return 0


async def _one_embed(session, sem, src, cutoff, cfg):
    from .extract import messages
    from .net import fetch
    text, _ = await fetch(session, src + '?embed=1&mode=tme', sem, cfg)
    if not text:
        return [], []
    p, u, _ = messages(text, cutoff, cfg)
    return p, u
