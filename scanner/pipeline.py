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


def _l3_pass(mode, tg, yt):
    """True/False/None(не проверялось). Непроверенное не отсеиваем."""
    if tg is None and yt is None:
        return True
    if mode == 'both':
        return tg is True and yt is True
    if mode == 'any':
        return tg is True or yt is True
    if mode == 'telegram':
        return tg is True
    if mode == 'youtube':
        return yt is True
    return True  # off


def _mark(tg, yt):
    if tg is None and yt is None:
        return ''
    tg_ok, yt_ok = tg is True, yt is True
    if tg_ok and yt_ok:
        return '🟢'
    if tg_ok:
        return '🟡'
    if yt_ok:
        return '🔵'
    return '⚪️'


def _tag(u, p, delays, l3_tg, l3_yt, tag_l3):
    """Имя прокси: метка сервисов + задержка. 🔴 = ядро сказало «мёртв»."""
    q = dict(p)
    if tag_l3:
        mk = _mark(l3_tg.get(u), l3_yt.get(u))
        if u in delays and not delays[u]:
            mk = '🔴'
        if mk:
            q['name'] = f"{mk} {q.get('name', '')}".strip()
    if delays.get(u):
        q['name'] = f"{q.get('name', '')} · {delays[u]}ms".strip(' ·')
    return q


async def run(config_path='config.yaml'):
    cfg = load(config_path)
    log.init(cfg)
    start = time.time()
    o = cfg.outputs

    if getattr(cfg.logging, 'diag_secrets', False):
        tg = cfg.telegram
        log.debug(f"секреты: api_id={'есть' if tg.api_id else 'ПУСТО'}, "
                  f"api_hash={len(tg.api_hash or '')} симв, "
                  f"session={len(tg.session_b64 or '')} симв")

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
    tg_fallback_web, tg_fallback_embed = list(web), list(embed)
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
            p, urls = await _read_web(session, http_sem, web, embed, cutoff_wl, cfg)
            items.extend(p)
            subs.update(clean_url(x) for x in urls)
            for w in web:
                visited.add(sub_key(w))
            log.debug(f'Каналы: ссылок {len(items)}, найдено подписок {len(subs)}')

        if tg:
            p, urls = await telethon_channels(tg, cutoff_wl, cfg)
            if not p and (tg_fallback_web or tg_fallback_embed):
                log.info('⚠️ Telethon ничего не дал — откат на t.me/s/')
                web, embed = tg_fallback_web, tg_fallback_embed
                p2, urls2 = await _read_web(session, http_sem, web, embed, cutoff_wl, cfg)
                items.extend(p2)
                subs.update(clean_url(x) for x in urls2)
                for w in web:
                    visited.add(sub_key(w))
            else:
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

        # ---------- дедуп по URI ----------
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

        # ---------- расклейка → дедуп → парсинг ----------
        fresh, origin, fallback, glued = [], {}, {}, 0
        for uri in merged:
            variants, tails = split_uri(uri)
            cand = variants[0]
            fresh.append(cand)
            origin.setdefault(cand, set()).add(uri)
            if len(variants) > 1:
                fallback[cand] = variants[1]
            if tails or len(variants) > 1:
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
            if p is None and rep in fallback:
                p2 = parse(fallback[rep])
                if p2 is not None:
                    p, used = p2, fallback[rep]
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

        # ---------- WL: только L0 + классификатор + L1 ----------
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

        level = int(cfg.verify.level)
        delays, geo, l3_tg, l3_yt = {}, {}, {}, {}
        core_checked = 0

        if level >= 1 and wl_items:
            tls_jobs = []
            for u, p in wl_items:
                if p.get('tls') and p.get('type') in ('vless', 'trojan', 'vmess'):
                    sni = p.get('server-name') or p.get('sni') or ''
                    tls_jobs.append((u, p['server'], p['port'], sni))
            if tls_jobs:
                tls_ok = await l1_tls(tls_jobs, cfg)
                wl_items = [(u, p) for u, p in wl_items if u not in tls_ok or tls_ok[u]]
                log.debug(f'🔐 после L1 осталось {len(wl_items)}')

        # ---------- L2 + L3: ТОЛЬКО общий список ----------
        # Белые через ядро не гоняем и не режем: с зарубежного раннера
        # RU-only прокси рвут соединение, L2 убивал 96% белых.
        if level >= 2:
            all_proto = set(cfg.protocols.all)
            pool = {u: p for u, p in alive
                    if dates.get(u, now_utc()) >= cutoff_all
                    and p.get('type') in all_proto}
            order = sorted(pool, key=lambda u: (-dates.get(u, now_utc()).timestamp(), u))
            cap = int(getattr(cfg.limits, 'core_max', 0) or 0)
            if cap > 0 and len(order) > cap:
                log.info(f'⚖️ ядро: лимит {cap} из {len(order)} кандидатов '
                         f'(остальные останутся в ALL без проверки)')
                order = order[:cap]

            if order:
                named = [(f'p{i}', dict(pool[u], name=f'p{i}'))
                         for i, u in enumerate(order)]
                idx = {f'p{i}': u for i, u in enumerate(order)}
                res = await l2_core(named, cfg, session)
                d, g, tg_raw, yt_raw = res if len(res) == 4 else (*res, {}, {})
                delays = {idx[k]: v for k, v in d.items() if k in idx}
                geo = {idx[k]: v for k, v in g.items() if k in idx}
                l3_tg = {idx[k]: v for k, v in tg_raw.items() if k in idx}
                l3_yt = {idx[k]: v for k, v in yt_raw.items() if k in idx}
                core_checked = len(order)

        cache.save()

    # ---------- сборка ALL ----------
    l3cfg = getattr(cfg.verify, 'l3', None)
    l3_on = bool(l3cfg and getattr(l3cfg, 'enabled', False))
    mode_all = getattr(l3cfg, 'require_mode_all', 'off') if l3cfg else 'off'
    mode_wl = getattr(l3cfg, 'require_mode_wl', 'off') if l3cfg else 'off'
    tag_l3 = bool(l3cfg and getattr(l3cfg, 'tag_names', True))
    keep_unchecked = bool(getattr(l3cfg, 'all_keep_unchecked', True)) if l3cfg else True
    drop_dead = bool(getattr(l3cfg, 'all_drop_dead', True)) if l3cfg else True

    all_proto = set(cfg.protocols.all)
    all_pool = [(u, p) for u, p in alive if dates.get(u, now_utc()) >= cutoff_all]
    n_before = len(all_pool)

    all_dead = all_dropped = all_unchecked = 0
    all_mode_used = mode_all

    # 1) выбрасываем доказанных мертвецов (L2 fail) — главный фильтр качества
    if drop_dead and delays:
        kept = []
        for u, p in all_pool:
            if u in delays and not delays[u]:
                all_dead += 1
                continue
            kept.append((u, p))
        all_pool = kept
        log.info(f'[L2] ALL: выброшено мёртвых {all_dead}, осталось {len(all_pool)}')

    # 2) фильтр по сервисам (TG/YT) среди проверенных
    if l3_on and mode_all != 'off' and (l3_tg or l3_yt):
        checked = [(u, p) for u, p in all_pool
                   if l3_tg.get(u) is not None or l3_yt.get(u) is not None]
        floor = float(getattr(l3cfg, 'min_keep_pct', 15)) / 100.0
        for candidate in (mode_all, 'any', 'off'):
            kept_n = sum(1 for u, _ in checked
                         if _l3_pass(candidate, l3_tg.get(u), l3_yt.get(u)))
            if not checked or kept_n >= max(1, int(len(checked) * floor)) or candidate == 'off':
                all_mode_used = candidate
                break
        if all_mode_used != mode_all:
            log.info(f'⚠️ L3 ALL: режим смягчён {mode_all} → {all_mode_used} '
                     f'(страховка min_keep_pct)')
        kept = []
        for u, p in all_pool:
            is_checked = l3_tg.get(u) is not None or l3_yt.get(u) is not None
            if not is_checked:
                if keep_unchecked:
                    kept.append((u, p))
                else:
                    all_unchecked += 1
                continue
            if _l3_pass(all_mode_used, l3_tg.get(u), l3_yt.get(u)):
                kept.append((u, p))
            else:
                all_dropped += 1
        all_pool = kept
        log.info(f'[L3] ALL режим={all_mode_used}: отсеяно по сервисам {all_dropped}, '
                 f'непроверенных убрано {all_unchecked}, осталось {len(all_pool)}')

    all_txt, all_clash, all_src = [], [], {}
    for u, p in all_pool:
        all_txt.append(u)
        if p.get('type') in all_proto and validate(p)[0]:
            all_clash.append(_tag(u, p, delays, l3_tg, l3_yt, tag_l3))
        for s in prov.get(u, ()):
            all_src[s] = all_src.get(s, 0) + 1

    # ---------- сборка WL (без фильтрации ядром) ----------
    wl_pairs, wl_src, wl_dropped = [], {}, 0
    for u, p in wl_items:
        if not validate(p)[0]:
            continue
        if l3_on and mode_wl != 'off' and not _l3_pass(mode_wl, l3_tg.get(u), l3_yt.get(u)):
            wl_dropped += 1
            continue
        q = _tag(u, p, delays, l3_tg, l3_yt, tag_l3)
        if u in geo:
            q['name'] = f"{geo[u]} · {q.get('name', '')}".strip(' ·')
        wl_pairs.append((u, q))
        for s in prov.get(u, ()):
            wl_src[s] = wl_src.get(s, 0) + 1
    if wl_dropped:
        log.info(f'[L3] WL режим={mode_wl}: отсеяно {wl_dropped}')

    all_clash = unique_names(all_clash)
    wl_clash = unique_names([p for _, p in wl_pairs])
    all_txt = sorted(set(all_txt))
    wl_txt = sorted({u for u, _ in wl_pairs})

    # ---------- best: топ по реальной задержке ----------
    verified = [(u, dict(p)) for u, p in wl_pairs if delays.get(u)]
    seen_v = {u for u, _ in verified}
    for u, p in all_pool:
        if not delays.get(u) or u in seen_v:
            continue
        if p.get('type') not in all_proto or not validate(p)[0]:
            continue
        verified.append((u, _tag(u, p, delays, l3_tg, l3_yt, tag_l3)))
        seen_v.add(u)
    best = sorted(verified, key=lambda up: (delays.get(up[0]) or 10 ** 9, up[0]))
    best = best[:int(cfg.limits.best)]
    best_txt = [u for u, _ in best]
    best_clash = unique_names([dict(p) for _, p in best])

    wl_verified = sum(1 for u, _ in wl_pairs if delays.get(u))
    stats = {
        'ts': now_utc().isoformat(),
        'raw': len(merged), 'candidates': len(fresh), 'reps': len(reps),
        'parsed': len(parsed), 'parse_fails': fails,
        'alive_l0': len(alive), 'core_checked': core_checked,
        'all_before': n_before, 'all': len(all_txt), 'all_yaml': len(all_clash),
        'wl': len(wl_txt), 'wl_yaml': len(wl_clash), 'best': len(best_txt),
        'wl_reasons': wl_reasons, 'wl_verified': wl_verified,
        'verify_level': level,
        'l3': {
            'checked_tg': len(l3_tg), 'checked_yt': len(l3_yt),
            'tg_ok': sum(1 for v in l3_tg.values() if v),
            'yt_ok': sum(1 for v in l3_yt.values() if v),
            'both_ok': sum(1 for u in l3_tg if l3_tg.get(u) and l3_yt.get(u)),
            'mode_all': mode_all, 'mode_all_used': all_mode_used,
            'mode_wl': mode_wl,
            'dropped_dead': all_dead, 'dropped_all': all_dropped,
            'dropped_unchecked': all_unchecked, 'dropped_wl': wl_dropped,
        },
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
              f'WL: txt={len(wl_txt)} yaml={len(wl_clash)} | best={len(best_txt)}')

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


async def _read_web(session, sem, web, embed, cutoff, cfg):
    jobs = [(u, web_channel(session, sem, u, cutoff, cfg.limits.tme_pages, cfg)) for u in web]
    jobs += [(u, _one_embed(session, sem, u, cutoff, cfg)) for u in embed]
    if not jobs:
        return [], []
    items, urls = [], []
    for (src, _), (p, u) in zip(jobs, await asyncio.gather(*(c for _, c in jobs))):
        items.extend((uri, dt, src) for uri, dt in p)
        urls.extend(u)
    return items, urls


async def _one_embed(session, sem, src, cutoff, cfg):
    from .extract import messages
    from .net import fetch
    text, _ = await fetch(session, src + '?embed=1&mode=tme', sem, cfg)
    if not text:
        return [], []
    p, u, _ = messages(text, cutoff, cfg)
    return p, u
