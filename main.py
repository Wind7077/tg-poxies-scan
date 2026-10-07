import os
import re
import base64
import asyncio
import yaml
import json
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import parse_qs, unquote, urlparse
from bs4 import BeautifulSoup
import aiohttp

try:
    from telethon import TelegramClient
    from telethon.tl.types import MessageEntityUrl, MessageEntityTextUrl
    TELETHON_OK = True
except ImportError:
    TELETHON_OK = False

# --- КОНФИГУРАЦИЯ ---
SOURCES_FILE = 'sources.txt'
OUT_TXT = 'proxy.txt'
OUT_YAML = 'proxy.yaml'
MAX_DAYS = 10
TIMEOUT = aiohttp.ClientTimeout(total=12, connect=7)
MAX_CONCURRENT_HTTP = 50
MAX_CONCURRENT_PING = 500

API_ID = int(os.getenv('TELEGRAM_API_ID', '0'))
API_HASH = os.getenv('TELEGRAM_API_HASH', '')
SESSION_B64 = os.getenv('TELEGRAM_SESSION', '')

PROXY_SCHEMES = ['vless', 'vmess', 'ss', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'happ']
PROXY_REGEX = re.compile(r'(?:' + '|'.join(PROXY_SCHEMES) + r')://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)
URL_REGEX = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)

BLACKLIST_DOMAINS = [
    't.me', 'telegram.org', 'telegram.me', 'telegra.ph',
    'github.com', 'youtube.com', 'youtu.be',
    'instagram.com', 'twitter.com', 'x.com',
    'vk.com', 'ok.ru', 'pikabu.ru', 'habr.com',
    'dzen.ru', 'yandex.ru', 'mail.ru', 'rambler.ru',
    'meduza.io', 'kommersant.ru', 'cnews.ru', 'iz.ru',
    'techradar.com', 'openai.com', 'sozd.duma.gov.ru',
    'playgta5.com', 'mrbeast.nocp.uz', 'cloud.mail.ru',
    'max.ru', 'git.a9fm.best', 'ria.ru', 'lenta.ru',
    'rbc.ru', 'vedomosti.ru', 'tass.ru',
    'git.arturlamaev.workers.dev', 'cyb-portal.org', 'gidroksi.fun',
    'h1cloud.net'
]

STICKY_WORDS = ['Gemini', 'Gemini:', 'Claude', 'ChatGPT']

DEBUG = True

def debug_log(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")

def decode_base64(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding: s += '=' * (4 - padding)
    try: return base64.b64decode(s).decode('utf-8', errors='ignore')
    except: return ""

def is_valid_url(url):
    try:
        r = urlparse(url)
        if not all([r.scheme, r.netloc]): return False
        if r.scheme == 'tg': return False
        if any(d in r.netloc for d in BLACKLIST_DOMAINS): return False
        return True
    except: return False

def is_useless_tme(url):
    if not ('t.me' in url or 'telegram.me' in url): return False
    if '/proxy?' in url or '/webproxy?' in url: return True
    if '/+' in url.split('//', 1)[-1][:10]: return True
    path = urlparse(url).path.strip('/')
    if '/' not in path and path.lower().endswith('bot'): return True
    return False

def split_glued(url):
    base = 8 if url.startswith('https://') else 7
    rest = url[base:]
    
    for proto in ['https://', 'http://']:
        idx = rest.find(proto)
        if idx > 0:
            char_before = rest[idx-1]
            if char_before != '/':
                return url[:base + idx]
    
    if url.count('@') >= 2:
        head = rest
        if '@' in head:
            at_idx = head.index('@')
            part_before_at = head[:at_idx]
            if '/' not in part_before_at and ':' not in part_before_at:
                return url[:base + at_idx]
    
    return url

def remove_sticky_words(url):
    for word in STICKY_WORDS:
        if url.endswith(word):
            url = url[:-len(word)]
    return url.rstrip('/')

def clean_url(url):
    for i, c in enumerate(url):
        if ord(c) > 127: url = url[:i]; break
    while url.endswith(')') and url.count(')') > url.count('('): url = url[:-1]
    url = split_glued(url.rstrip('.,;:!?'))
    url = remove_sticky_words(url)
    return url

def collect_url(raw, urls):
    u = clean_url(raw)
    if not u: return
    if 't.me' in u or 'telegram.me' in u:
        if not is_useless_tme(u): urls.append(u)
    elif is_valid_url(u):
        urls.append(u)

def make_names_unique(proxies):
    """Делает имена прокси уникальными для Clash/FlClash"""
    used = {}
    renamed = 0
    for p in proxies:
        name = (p.get('name') or '').strip()
        if not name:
            name = f"{p.get('type', 'proxy')}-{p.get('server', 'unknown')}:{p.get('port', 0)}"
        
        base_name = name
        if name in used:
            used[name] += 1
            name = f"{base_name} #{used[name]}"
            renamed += 1
        else:
            used[name] = 1
        
        p['name'] = name
    
    if renamed:
        debug_log(f"🏷️ Переименовано дубликатов имён: {renamed}")
    return proxies

def extract_from_element(element):
    proxies, urls = [], []
    if hasattr(element, 'find_all'):
        for a in element.find_all('a', href=True):
            href = a['href'].strip()
            if any(href.startswith(f"{s}://") for s in PROXY_SCHEMES):
                proxies.append(clean_url(href))
            elif href.startswith('http'):
                collect_url(href, urls)
    text = element.get_text() if hasattr(element, 'get_text') else str(element)
    proxies.extend([clean_url(m.group(0)) for m in PROXY_REGEX.finditer(text)])
    for m in URL_REGEX.finditer(text):
        collect_url(m.group(0), urls)
    return list(set(proxies)), list(set(urls))

async def fetch(session, url, sem, retry_count=2):
    async with sem:
        try:
            if not url.startswith(('http://', 'https://')): return ""
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            if 'kfwl.lol' in url:
                headers['Referer'] = 'https://t.me/'
            
            timeout = TIMEOUT
            problem_domains = ['kfwl.lol', 'pozor.bond', 'atlanta-subs.ru', 'astra-sub.com', 'taurus-sync.com', 'net4.su']
            if any(d in url for d in problem_domains):
                timeout = aiohttp.ClientTimeout(total=30, connect=10)
            
            for attempt in range(retry_count + 1):
                try:
                    async with session.get(url, headers=headers, allow_redirects=True, ssl=False, timeout=timeout) as resp:
                        if resp.status == 200:
                            data = await resp.read()
                            text = data.decode('utf-8', errors='ignore')
                            debug_log(f"✓ {url[:80]}: {len(text)} симв.")
                            return text
                        elif resp.status in [403, 429, 503]:
                            if attempt < retry_count:
                                debug_log(f"⏳ {resp.status} для {url[:60]}, retry {attempt+1}...")
                                await asyncio.sleep(2 * (attempt + 1))
                                continue
                            debug_log(f"✗ {resp.status} для {url[:80]} (после {retry_count} попыток)")
                            return ""
                        else:
                            debug_log(f"✗ {resp.status} для {url[:80]}")
                            return ""
                except (asyncio.TimeoutError, aiohttp.ServerTimeoutError):
                    if attempt < retry_count:
                        debug_log(f"⏳ Timeout для {url[:60]}, retry {attempt+1}...")
                        await asyncio.sleep(2 * (attempt + 1))
                        continue
                    debug_log(f"✗ Timeout для {url[:80]} (после {retry_count} попыток)")
                    return ""
                except Exception as e:
                    if attempt < retry_count:
                        await asyncio.sleep(1)
                        continue
                    debug_log(f"✗ {url[:80]}: {type(e).__name__}")
                    return ""
        except Exception as e:
            debug_log(f"✗ {url[:80]}: {type(e).__name__}")
        return ""

def extract_messages_data(html, cutoff_date):
    soup = BeautifulSoup(html, 'html.parser')
    messages = soup.find_all('div', class_='tgme_widget_message')
    p, u = [], []
    for msg in messages:
        time_tag = msg.find('time')
        if time_tag and time_tag.get('datetime'):
            try:
                dt = datetime.fromisoformat(time_tag['datetime'].replace('Z', '+00:00'))
                if dt < cutoff_date: continue
            except: pass
        px, ur = extract_from_element(msg)
        p.extend(px); u.extend(ur)
    debug_log(f"Найдено сообщений: {len(messages)}")
    return p, u

async def parse_with_telethon(source_url, cutoff_date):
    if not SESSION_B64 or not TELETHON_OK or API_ID == 0:
        debug_log("Telethon не настроен (нет API ключей или сессии)")
        return [], []
    
    match = re.match(r'https?://t\.me/(?:c/)?([a-zA-Z0-9_]+)(?:/(\d+))?', source_url)
    if not match: return [], []
    
    chat_id = match.group(1)
    topic_id = int(match.group(2)) if match.group(2) else None
    
    if '/c/' in source_url:
        try: chat_id = int(f"-100{chat_id}")
        except: pass
    
    session_file = 'tg_session'
    try:
        session_data = base64.b64decode(SESSION_B64)
        with open(session_file + '.session', 'wb') as f:
            f.write(session_data)
        debug_log(f"Сессия восстановлена ({len(session_data)} байт)")
    except Exception as e:
        debug_log(f"Ошибка восстановления сессии: {e}")
        return [], []
    
    proxies, urls = [], []
    client = None
    try:
        client = TelegramClient(session_file, API_ID, API_HASH)
        await client.connect()
        
        if not await client.is_user_authorized():
            debug_log("❌ Сессия не авторизована!")
            return [], []
        
        debug_log(f"Telethon: читаем {chat_id} (топик {topic_id})...")
        
        try:
            entity = await client.get_entity(chat_id)
        except Exception as e:
            debug_log(f"❌ Не удалось получить entity {chat_id}: {type(e).__name__}: {e}")
            return [], []
        
        msg_count = 0
        try:
            async for msg in client.iter_messages(entity, limit=300):
                if not msg.date: continue
                msg_date = msg.date.replace(tzinfo=timezone.utc)
                if msg_date < cutoff_date:
                    debug_log(f"Достигнут cutoff ({msg_count} сообщений)")
                    break
                
                msg_count += 1
                text = msg.text or msg.message or ''
                
                for m in PROXY_REGEX.finditer(text):
                    proxies.append(clean_url(m.group(0)))
                for m in URL_REGEX.finditer(text):
                    collect_url(m.group(0), urls)
                
                if msg.entities:
                    for ent in msg.entities:
                        if isinstance(ent, MessageEntityTextUrl) and ent.url:
                            u = clean_url(ent.url)
                            if any(u.startswith(f"{s}://") for s in PROXY_SCHEMES):
                                proxies.append(u)
                            else:
                                collect_url(ent.url, urls)
        except Exception as e:
            debug_log(f"❌ Ошибка итерации сообщений: {type(e).__name__}: {e}")
        
        debug_log(f"Telethon ✅: {len(proxies)} прокси, {len(urls)} URL из {chat_id} ({msg_count} сообщений)")
        
    except Exception as e:
        debug_log(f"❌ Telethon ошибка: {type(e).__name__}: {e}")
    finally:
        if client:
            try: await client.disconnect()
            except: pass
        try: os.remove(session_file + '.session')
        except: pass
    
    return list(set(proxies)), list(set(urls))

async def process_subscription(url, session, sem, visited):
    if url in visited: return []
    visited.add(url)
    
    if url.startswith('happ://'): return [url]
    if not url.startswith(('http://', 'https://')): return []
    if is_useless_tme(url): return []
    
    if 'kfwl.lol' in url:
        text = await fetch(session, url, sem, retry_count=1)
        if not text or len(text) < 50:
            return []
        
        decoded = decode_base64(text)
        search_text = decoded if decoded and len(decoded) > 50 else text
        found = [clean_url(p) for p in PROXY_REGEX.findall(search_text)]
        if len(found) == 0 and 'net4.su' in url:
            debug_log(f"⚠️ Форма вместо прокси в {url[:60]}")
        if found: debug_log(f"✓ {len(found)} прокси в {url[:60]}")
        return found
    
    text = await fetch(session, url, sem)
    if not text: return []
    decoded = decode_base64(text)
    search_text = decoded if decoded and len(decoded) > 50 else text
    found = [clean_url(p) for p in PROXY_REGEX.findall(search_text)]
    if found: debug_log(f"✓ {len(found)} прокси в {url[:60]}")
    return found

async def check_proxy_tcp(host, port, sem):
    async with sem:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=2.0)
            w.close(); await w.wait_closed()
            return True
        except: return False

def parse_uri_for_clash(uri):
    try:
        s, rest = uri.split('://', 1); s = s.lower()
        if s == 'happ': return None
        if s == 'vmess':
            d = json.loads(decode_base64(rest))
            return {'name': d.get('ps', f"VM-{d.get('add')}"), 'type': 'vmess', 'server': d.get('add'), 'port': int(d.get('port', 0)), 'uuid': d.get('id', ''), 'alterId': int(d.get('aid', 0)), 'cipher': 'auto', 'tls': d.get('tls')=='tls', 'network': d.get('net', 'tcp'), 'udp': True}
        elif s == 'trojan':
            pw, r2 = rest.split('@', 1); hp, pn = r2.split('?', 1) if '?' in r2 else (r2, ''); h, p = hp.split(':', 1)
            n = unquote(pn.split('#', 1)[1]) if '#' in pn else f"T-{h}"
            return {'name': n, 'type': 'trojan', 'server': h, 'port': int(p), 'password': pw, 'udp': True}
        elif s == 'vless':
            u, r2 = rest.split('@', 1); hp, pn = r2.split('?', 1) if '?' in r2 else (r2, ''); h, p = hp.split(':', 1)
            n = unquote(pn.split('#', 1)[1]) if '#' in pn else f"V-{h}"
            q = parse_qs(pn.split('#')[0]) if '?' in pn else {}; nt = q.get('type', ['tcp'])[0]
            res = {'name': n, 'type': 'vless', 'server': h, 'port': int(p), 'uuid': u, 'network': nt, 'udp': True, 'tls': q.get('security', [''])[0] in ['tls', 'reality']}
            if nt == 'ws': res['ws-opts'] = {'path': unquote(q.get('path', ['/'])[0])}
            return res
        elif s == 'ss':
            if '@' in rest:
                ui, hp = rest.split('@', 1)
                if ':' in hp:
                    h, p = hp.split(':', 1)
                    if ':' in ui: c, pw = ui.split(':', 1)
                    else: c, pw = 'aes-256-gcm', decode_base64(ui)
                    return {'name': f"SS-{h}", 'type': 'ss', 'server': h, 'port': int(p.split('#')[0]), 'cipher': c, 'password': pw, 'udp': True}
        elif s in ['hysteria', 'hysteria2', 'hy2']:
            ar, pn = rest.split('?', 1) if '?' in rest else (rest, '')
            if '@' in ar: pw, hp = ar.split('@', 1)
            else: pw, hp = '', ar
            if ':' in hp:
                h, p = hp.split(':', 1)
                n = unquote(pn.split('#', 1)[1]) if '#' in pn else f"H-{h}"
                return {'name': n, 'type': 'hysteria2' if s=='hy2' else s, 'server': h, 'port': int(p), 'password': pw, 'udp': True}
    except: pass
    return None

async def main():
    start = time.time()
    if not os.path.exists(SOURCES_FILE):
        print("sources.txt не найден!"); return
    
    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    
    http_sem = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
    ping_sem = asyncio.Semaphore(MAX_CONCURRENT_PING)
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_DAYS)
    
    all_proxies, sub_urls, visited = [], set(), set()
    
    web_sources, telethon_sources = [], []
    for src in sources:
        if not src.startswith('http'): continue
        if src.startswith('https://t.me/'):
            if 'LowiKForum' in src or any(x in src.lower() for x in ['chat', 'forum']):
                telethon_sources.append(src)
            else:
                web_sources.append(src)
        else:
            sub_urls.add(clean_url(src))
    
    print(f"[{time.time()-start:.1f}s] Web: {len(web_sources)}, Telethon: {len(telethon_sources)}")
    
    if web_sources:
        async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
            tasks = []
            for src in web_sources:
                if re.search(r'/\d+$', src):
                    url = f"{src}?embed=1&mode=tme"
                else:
                    url = src.replace('https://t.me/', 'https://t.me/s/')
                tasks.append((url, fetch(session, url, http_sem)))
            results = await asyncio.gather(*[t[1] for t in tasks])
            for (u, _), html in zip(tasks, results):
                if html:
                    p, u2 = extract_messages_data(html, cutoff)
                    debug_log(f"Из {u[:60]}: {len(p)} прокси, {len(u2)} URL")
                    all_proxies.extend(p)
                    for l in u2: sub_urls.add(clean_url(l))
    
    if telethon_sources:
        if TELETHON_OK and SESSION_B64 and API_ID != 0:
            print(f"[{time.time()-start:.1f}s] Парсим через Telethon ({len(telethon_sources)} источников)...")
            for src in telethon_sources:
                p, u = await parse_with_telethon(src, cutoff)
                all_proxies.extend(p)
                for l in u: sub_urls.add(clean_url(l))
        else:
            debug_log(f"⚠️ Telethon не настроен, пропускаем {len(telethon_sources)} источников")
    
    if sub_urls:
        clean_subs = set()
        for url in sub_urls:
            u = url.rstrip('/')
            if u not in clean_subs:
                clean_subs.add(u)
        
        print(f"[{time.time()-start:.1f}s] Обрабатываем {len(clean_subs)} подписок...")
        async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
            tasks = [process_subscription(url, session, http_sem, visited) for url in clean_subs]
            results = await asyncio.gather(*tasks)
            for r in results: all_proxies.extend(r)
    
    all_proxies = [p for p in set(all_proxies) if p and '://' in p]
    print(f"[{time.time()-start:.1f}s] Сырых прокси: {len(all_proxies)}")
    
    happ, ping_list = [], []
    for u in all_proxies:
        (happ if u.lower().startswith('happ://') else ping_list).append(u)
    
    print(f"[{time.time()-start:.1f}s] Пингуем {len(ping_list)} серверов...")
    alive = []
    tasks, pmap = [], {}
    for u in ping_list:
        parsed = parse_uri_for_clash(u)
        if parsed and parsed.get('server') and parsed.get('port'):
            tasks.append(check_proxy_tcp(parsed['server'], parsed['port'], ping_sem))
            pmap[len(tasks)-1] = (u, parsed)
    if tasks:
        results = await asyncio.gather(*tasks)
        for i, ok in enumerate(results):
            if ok: alive.append(pmap[i])
    print(f"[{time.time()-start:.1f}s] Живых: {len(alive)}")
    
    # Сохранение в proxy.txt (plain text)
    alive_uris = [u for u, _ in alive]
    all_uris = alive_uris + happ
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    header = [f"# Обновлено: {ts}", f"# Живых: {len(alive_uris)}", f"# Happ: {len(happ)}", "#"]
    with open(OUT_TXT, 'w', encoding='utf-8') as f:
        f.write("\n".join(header + all_uris))
    
    # Сохранение в proxy.yaml (Clash) С УНИКАЛЬНЫМИ ИМЕНАМИ
    clash_proxies = [p for _, p in alive]
    clash_proxies = make_names_unique(clash_proxies)
    names = [p['name'] for p in clash_proxies] if clash_proxies else ['DIRECT']
    clash_config = {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'Rule', 'log-level': 'info',
        'external-controller': '127.0.0.1:9090', 'proxies': clash_proxies,
        'proxy-groups': [
            {'name': '♻️ Auto', 'type': 'url-test', 'proxies': names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
            {'name': '🚀 Proxy', 'type': 'select', 'proxies': ['♻️ Auto'] + names}
        ],
        'rules': ['MATCH,🚀 Proxy']
    }
    with open(OUT_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, sort_keys=False, allow_unicode=True)
    
    print(f"✅ Готово за {time.time()-start:.1f} сек!")

if __name__ == '__main__':
    asyncio.run(main())
