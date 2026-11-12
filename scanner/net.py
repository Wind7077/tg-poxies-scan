import asyncio

import aiohttp

from . import log


def headers_for(url):
    if 't.me/' in url or 'telegram.me/' in url:
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8',
        }
    return {
        'User-Agent': 'Happ/1.0 (com.happ; build:100; iOS 17.0.0) Alamofire/5.8.0',
        'Accept': '*/*',
        'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8',
    }


def make_session(cfg):
    t = cfg.timeouts
    connector = aiohttp.TCPConnector(limit=int(cfg.concurrency.http), ttl_dns_cache=300, ssl=False)
    timeout = aiohttp.ClientTimeout(total=float(t.http_total), connect=float(t.http_connect))
    return aiohttp.ClientSession(connector=connector, timeout=timeout)


async def fetch(session, url, sem, cfg, cache=None, retry_count=2):
    """-> (text, not_modified). В лог только счётчики."""
    if not url.startswith(('http://', 'https://')):
        return '', False
    h = headers_for(url)
    if 'kfwl.lol' in url:
        h['Referer'] = 'https://t.me/'
    if cache:
        h.update(cache.validators(url))
    t = cfg.timeouts
    long_to = aiohttp.ClientTimeout(total=float(t.long_total), connect=10)
    timeout = long_to if any(d in url for d in cfg.problem_domains) else None

    for attempt in range(retry_count + 1):
        retryable = False
        try:
            async with sem:
                kwargs = {'headers': h, 'allow_redirects': True}
                if timeout:
                    kwargs['timeout'] = timeout
                async with session.get(url, **kwargs) as resp:
                    if resp.status == 304:
                        log.STATS['http_304'] += 1
                        log.progress()
                        return '', True
                    if resp.status == 200:
                        data = await resp.read()
                        log.STATS['http_ok'] += 1
                        log.STATS['bytes'] += len(data)
                        log.progress()
                        return data.decode('utf-8', errors='ignore'), False
                    retryable = resp.status in (403, 429, 500, 502, 503, 504)
        except asyncio.CancelledError:
            raise
        except Exception:
            retryable = True
        if not retryable or attempt == retry_count:
            log.STATS['http_fail'] += 1
            log.progress()
            return '', False
        await asyncio.sleep(2 * (attempt + 1))
    log.STATS['http_fail'] += 1
    return '', False


async def ping(host, port, sem, timeout):
    async with sem:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=timeout)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return True
        except asyncio.CancelledError:
            raise
        except Exception:
            return False
