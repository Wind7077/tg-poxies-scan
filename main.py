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

# --- КОНФИГУРАЦИЯ ---
SOURCES_FILE = 'sources.txt'
OUT_TXT = 'proxy.txt'
OUT_YAML = 'proxy.yaml'
MAX_DAYS = 10
TIMEOUT = aiohttp.ClientTimeout(total=7, connect=5)
MAX_CONCURRENT_HTTP = 50
MAX_CONCURRENT_PING = 200

PROXY_SCHEMES = ['vless', 'vmess', 'ss', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'happ']
# Улучшенная регулярка - обрезаем всё, что не URL (включая эмодзи)
PROXY_REGEX = re.compile(r'(' + '|'.join(PROXY_SCHEMES) + r')://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)
URL_REGEX = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)

BLACKLIST_DOMAINS = ['t.me', 'telegram.org', 'telegram.me', 'telegra.ph', 'github.com', 'youtube.com', 'youtu.be', 'instagram.com', 'twitter.com', 'x.com']

DEBUG = True

def debug_log(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")

def decode_base64(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding:
        s += '=' * (4 - padding)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def is_valid_url(url):
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False
        if result.scheme == 'tg':  # Фильтруем tg:// ссылки
            return False
        if any(d in result.netloc for d in BLACKLIST_DOMAINS):
            return False
        return True
    except Exception:
        return False

def clean_url(url):
    """Убирает мусор с конца URL (эмодзи и пр.)"""
    # Обрезаем на первом не-ASCII символе
    for i, char in enumerate(url):
        if ord(char) > 127:
            return url[:i]
    return url

def extract_from_element(element):
    proxies, urls = [], []
    
    # Извлекаем из <a> тегов
    if hasattr(element, 'find_all'):
        for a in element.find_all('a', href=True):
            href = clean_url(a['href'].strip())
            if any(href.startswith(f"{s}://") for s in PROXY_SCHEMES):
                proxies.append(href)
            elif href.startswith('http'):
                urls.append(href)
    
    # Извлекаем из текста
    text = element.get_text() if hasattr(element, 'get_text') else str(element)
    
    # Ищем прокси
    for match in PROXY_REGEX.finditer(text):
        proxies.append(clean_url(match.group(0)))
    
    # Ищем URL
    for match in URL_REGEX.finditer(text):
        url = clean_url(match.group(0))
        if is_valid_url(url):
            urls.append(url)
    
    return list(set(proxies)), list(set(urls))

async def fetch(session, url, sem):
    async with sem:
        try:
            # Фильтруем не-HTTP схемы
            if not url.startswith(('http://', 'https://')):
                return ""
            
            async with session.get(url, allow_redirects=True, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    debug_log(f"✓ Скачано {url[:80]}: {len(text)} символов")
                    return text
                else:
                    debug_log(f"✗ Ошибка {resp.status} для {url[:80]}")
        except Exception as e:
            debug_log(f"✗ Исключение {url[:80]}: {type(e).__name__}")
        return ""

def extract_messages_data(html, cutoff_date):
    soup = BeautifulSoup(html, 'html.parser')
    messages = soup.find_all('div', class_='tgme_widget_message')
    
    all_proxies, all_urls = [], []
    debug_log(f"Найдено сообщений: {len(messages)}")
    
    for msg in messages:
        time_tag = msg.find('time')
        if time_tag and time_tag.get('datetime'):
            try:
                dt_str = time_tag['datetime'].replace('Z', '+00:00')
                post_time = datetime.fromisoformat(dt_str)
                if post_time < cutoff_date:
                    continue
            except Exception:
                pass
                
        p, u = extract_from_element(msg)
        all_proxies.extend(p)
        all_urls.extend(u)
        
    return all_proxies, all_urls

async def process_subscription(url, session, sem, visited_subs):
    if url in visited_subs:
        return []
    visited_subs.add(url)
    
    if url.startswith('happ://'):
        return [url]
    
    if not url.startswith(('http://', 'https://')):
        return []
        
    text = await fetch(session, url, sem)
    if not text:
        return []
    
    proxies = []
    
    # Пробуем base64
    decoded = decode_base64(text)
    search_text = decoded if decoded and len(decoded) > 50 else text
    
    # Ищем прокси
    found = [clean_url(p) for p in PROXY_REGEX.findall(search_text)]
    if found:
        debug_log(f"✓ Найдено {len(found)} прокси в {url[:60]}")
        proxies.extend(found)
    
    return proxies

async def check_proxy_tcp(host, port, sem):
    async with sem:
        try:
            port_int = int(port)
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port_int), 
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

def parse_uri_for_clash(uri):
    try:
        scheme, rest = uri.split('://', 1)
        scheme = scheme.lower()
        if scheme == 'happ':
            return None
        
        if scheme == 'vmess':
            data = json.loads(decode_base64(rest))
            return {
                'name': data.get('ps', f"VMess-{data.get('add')}"),
                'type': 'vmess',
                'server': data.get('add'),
                'port': int(data.get('port', 0)),
                'uuid': data.get('id', ''),
                'alterId': int(data.get('aid', 0)),
                'cipher': 'auto',
                'tls': data.get('tls') == 'tls',
                'network': data.get('net', 'tcp'),
                'udp': True
            }
        elif scheme == 'trojan':
            password, rest2 = rest.split('@', 1)
            host_port, params_name = rest2.split('?', 1) if '?' in rest2 else (rest2, '')
            host, port = host_port.split(':', 1)
            name = unquote(params_name.split('#', 1)[1]) if '#' in params_name else f"Trojan-{host}"
            return {
                'name': name,
                'type': 'trojan',
                'server': host,
                'port': int(port),
                'password': password,
                'udp': True
            }
        elif scheme == 'vless':
            uuid, rest2 = rest.split('@', 1)
            host_port, params_name = rest2.split('?', 1) if '?' in rest2 else (rest2, '')
            host, port = host_port.split(':', 1)
            name = unquote(params_name.split('#', 1)[1]) if '#' in params_name else f"VLESS-{host}"
            query = parse_qs(params_name.split('#')[0]) if '?' in params_name else {}
            net = query.get('type', ['tcp'])[0]
            p = {
                'name': name,
                'type': 'vless',
                'server': host,
                'port': int(port),
                'uuid': uuid,
                'network': net,
                'udp': True,
                'tls': query.get('security', [''])[0] in ['tls', 'reality']
            }
            if net == 'ws':
                p['ws-opts'] = {'path': unquote(query.get('path', ['/'])[0])}
            return p
        elif scheme == 'ss':
            if '@' in rest:
                userinfo, hostport = rest.split('@', 1)
                if ':' in hostport:
                    host, port = hostport.split(':', 1)
                    if ':' in userinfo:
                        cipher, password = userinfo.split(':', 1)
                    else:
                        cipher, password = 'aes-256-gcm', decode_base64(userinfo)
                    return {
                        'name': f"SS-{host}",
                        'type': 'ss',
                        'server': host,
                        'port': int(port.split('#')[0]),
                        'cipher': cipher,
                        'password': password,
                        'udp': True
                    }
        elif scheme in ['hysteria', 'hysteria2', 'hy2']:
            auth_rest, params_name = rest.split('?', 1) if '?' in rest else (rest, '')
            if '@' in auth_rest:
                password, host_port = auth_rest.split('@', 1)
            else:
                password, host_port = '', auth_rest
            if ':' in host_port:
                host, port = host_port.split(':', 1)
                name = unquote(params_name.split('#', 1)[1]) if '#' in params_name else f"Hysteria-{host}"
                return {
                    'name': name,
                    'type': 'hysteria2' if scheme == 'hy2' else scheme,
                    'server': host,
                    'port': int(port),
                    'password': password,
                    'udp': True
                }
    except Exception:
        pass
    return None

async def main():
    start_time = time.time()
    
    if not os.path.exists(SOURCES_FILE):
        print("Файл sources.txt не найден!")
        return

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    http_sem = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
    ping_sem = asyncio.Semaphore(MAX_CONCURRENT_PING)
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=MAX_DAYS)
    
    all_proxies = []
    sub_urls = set()
    visited_subs = set()

    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
        print(f"[{time.time()-start_time:.1f}s] Скачиваем {len(sources)} источников...")
        
        source_tasks = []
        for src in sources:
            if not src.startswith('http'):
                continue
            if src.startswith('https://t.me/'):
                # Проверяем, это топик или канал
                if re.search(r'/\d+$', src):
                    # Топик - используем embed формат
                    web_url = f"{src}?embed=1&mode=tme"
                else:
                    # Канал - используем /s/
                    web_url = src.replace('https://t.me/', 'https://t.me/s/')
                source_tasks.append((web_url, fetch(session, web_url, http_sem)))
            else:
                sub_urls.add(clean_url(src))
        
        results = await asyncio.gather(*[t[1] for t in source_tasks])
        
        for (url, _), html in zip(source_tasks, results):
            if html:
                p, u = extract_messages_data(html, cutoff_date)
                debug_log(f"Из {url[:60]}: {len(p)} прокси, {len(u)} URL подписок")
                all_proxies.extend(p)
                for link in u:
                    sub_urls.add(clean_url(link))
        
        print(f"[{time.time()-start_time:.1f}s] Найдено ссылок на подписки: {len(sub_urls)}")

        print(f"[{time.time()-start_time:.1f}s] Обрабатываем подписки...")
        sub_tasks = [process_subscription(url, session, http_sem, visited_subs) for url in sub_urls]
        sub_results = await asyncio.gather(*sub_tasks)
        
        for res in sub_results:
            all_proxies.extend(res)

    # Уникализация
    all_proxies = [p for p in set(all_proxies) if p and '://' in p]
    print(f"[{time.time()-start_time:.1f}s] Найдено сырых прокси: {len(all_proxies)}")

    happ_links = []
    proxies_to_ping = []
    for uri in all_proxies:
        if uri.lower().startswith('happ://'):
            happ_links.append(uri)
        else:
            proxies_to_ping.append(uri)

    print(f"[{time.time()-start_time:.1f}s] Пингуем {len(proxies_to_ping)} серверов...")
    alive_proxies = []
    ping_tasks = []
    proxy_map = {}
    
    for uri in proxies_to_ping:
        parsed = parse_uri_for_clash(uri)
        if parsed and parsed.get('server') and parsed.get('port'):
            ping_tasks.append(check_proxy_tcp(parsed['server'], parsed['port'], ping_sem))
            proxy_map[len(ping_tasks)-1] = (uri, parsed)
            
    if ping_tasks:
        results = await asyncio.gather(*ping_tasks)
        for i, is_alive in enumerate(results):
            if is_alive:
                alive_proxies.append(proxy_map[i])
                
    print(f"[{time.time()-start_time:.1f}s] Живых серверов: {len(alive_proxies)}")

    # Сохранение
    alive_uris = [uri for uri, _ in alive_proxies]
    all_uris = alive_uris + happ_links 
    
    raw_txt = "\n".join(all_uris)
    b64_txt = base64.b64encode(raw_txt.encode('utf-8')).decode('utf-8')
    with open(OUT_TXT, 'w', encoding='utf-8') as f:
        f.write(b64_txt)
        
    clash_proxies = [p for _, p in alive_proxies]
    proxy_names = [p['name'] for p in clash_proxies] if clash_proxies else ['DIRECT']
    
    clash_config = {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'Rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': clash_proxies,
        'proxy-groups': [
            {
                'name': '♻️ Auto',
                'type': 'url-test',
                'proxies': proxy_names,
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300
            },
            {
                'name': '🚀 Proxy',
                'type': 'select',
                'proxies': ['♻️ Auto'] + proxy_names
            }
        ],
        'rules': ['MATCH,🚀 Proxy']
    }
    
    with open(OUT_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, sort_keys=False, allow_unicode=True)
        
    print(f"✅ Готово за {time.time()-start_time:.1f} секунд!")

if __name__ == '__main__':
    asyncio.run(main())
