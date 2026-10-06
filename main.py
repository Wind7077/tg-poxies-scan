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
    from telethon.tl.types import MessageMediaDocument, MessageEntityUrl, MessageEntityTextUrl
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False

# --- КОНФИГУРАЦИЯ ---
SOURCES_FILE = 'sources.txt'
OUT_TXT = 'proxy.txt'
OUT_YAML = 'proxy.yaml'
SESSION_FILE = 'telegram_session'
MAX_DAYS = 10
TIMEOUT = aiohttp.ClientTimeout(total=7, connect=5)
MAX_CONCURRENT_HTTP = 50
MAX_CONCURRENT_PING = 200

# Telethon API (заполните своими данными)
API_ID = int(os.getenv('TELEGRAM_API_ID', '0'))
API_HASH = os.getenv('TELEGRAM_API_HASH', '')

PROXY_SCHEMES = ['vless', 'vmess', 'ss', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'happ']
PROXY_REGEX = re.compile(r'(?:' + '|'.join(PROXY_SCHEMES) + r')://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)
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
        if result.scheme == 'tg':
            return False
        if any(d in result.netloc for d in BLACKLIST_DOMAINS):
            return False
        return True
    except Exception:
        return False

def clean_url(url):
    for i, char in enumerate(url):
        if ord(char) > 127:
            url = url[:i]
            break
    while url.endswith(')') and url.count(')') > url.count('('):
        url = url[:-1]
    url = url.rstrip('.,;:!?')
    return url

# ========================================
# ЧАСТЬ 1: ПАРСИНГ ЧЕРЕЗ WEB PREVIEW
# (для публичных каналов)
# ========================================

def extract_from_element(element):
    proxies, urls = [], []
    if hasattr(element, 'find_all'):
        for a in element.find_all('a', href=True):
            href = clean_url(a['href'].strip())
            if any(href.startswith(f"{s}://") for s in PROXY_SCHEMES):
                proxies.append(href)
            elif href.startswith('http'):
                urls.append(href)
    text = element.get_text() if hasattr(element, 'get_text') else str(element)
    for match in PROXY_REGEX.finditer(text):
        proxies.append(clean_url(match.group(0)))
    for match in URL_REGEX.finditer(text):
        url = clean_url(match.group(0))
        if is_valid_url(url):
            urls.append(url)
    return list(set(proxies)), list(set(urls))

async def fetch(session, url, sem):
    async with sem:
        try:
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

# ========================================
# ЧАСТЬ 2: ПАРСИНГ ЧЕРЕЗ TELETHON (MTProto)
# (для чатов, групп, закрытых каналов)
# ========================================

async def parse_with_telethon(source_url, cutoff_date):
    """
    Парсит источник через Telethon (MTProto API).
    Работает для чатов, групп, закрытых каналов, топиков.
    """
    if not TELETHON_AVAILABLE:
        debug_log("Telethon не установлен, пропускаем")
        return [], []
    
    if API_ID == 0 or not API_HASH:
        debug_log("API_ID/API_HASH не настроены, пропускаем Telethon")
        return [], []
    
    # Определяем тип источника
    match = re.match(r'https?://t\.me/([a-zA-Z0-9_]+)(?:/(\d+))?', source_url)
    if not match:
        return [], []
    
    chat_name = match.group(1)
    topic_id = int(match.group(2)) if match.group(2) else None
    
    proxies, urls = [], []
    
    try:
        # Подключаемся к Telegram
        client = TelegramClient(SESSION_FILE, API_ID, API_HASH)
        await client.start(bot_token=os.getenv('TELEGRAM_BOT_TOKEN'))
        
        # Получаем сущность чата
        try:
            entity = await client.get_entity(chat_name)
        except Exception as e:
            debug_log(f"Не удалось получить сущность {chat_name}: {e}")
            await client.disconnect()
            return [], []
        
        debug_log(f"Подключились к {chat_name}, парсим сообщения...")
        
        # Параметры для iter_messages
        kwargs = {
            'entity': entity,
            'limit': 200,  # Последние 200 сообщений
            'offset_date': datetime.now(timezone.utc),
        }
        
        # Если это топик - добавляем topic_id
        if topic_id:
            kwargs['reply_to'] = topic_id  # Может не работать, пробуем
        
        # Итерируем по сообщениям
        async for message in client.iter_messages(**kwargs):
            # Проверка даты
            if message.date and message.date.replace(tzinfo=timezone.utc) < cutoff_date:
                break  # Сообщения идут от новых к старым, можно остановиться
            
            text = message.text or message.message or ''
            
            # Ищем прокси в тексте
            for match in PROXY_REGEX.finditer(text):
                proxies.append(clean_url(match.group(0)))
            
            # Ищем URL подписок
            for match in URL_REGEX.finditer(text):
                url = clean_url(match.group(0))
                if is_valid_url(url):
                    urls.append(url)
            
            # Также проверяем entities (ссылки в тексте)
            if message.entities:
                for entity in message.entities:
                    if isinstance(entity, (MessageEntityUrl, MessageEntityTextUrl)):
                        if hasattr(entity, 'url') and entity.url:
                            url = clean_url(entity.url)
                            if is_valid_url(url):
                                urls.append(url)
                            elif any(url.startswith(f"{s}://") for s in PROXY_SCHEMES):
                                proxies.append(url)
        
        await client.disconnect()
        debug_log(f"Из {chat_name} (Telethon): {len(proxies)} прокси, {len(urls)} URL")
        
    except Exception as e:
        debug_log(f"Ошибка Telethon для {chat_name}: {type(e).__name__}: {e}")
    
    return list(set(proxies)), list(set(urls))

# ========================================
# ОБЩАЯ ЛОГИКА
# ========================================

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
    decoded = decode_base64(text)
    search_text = decoded if decoded and len(decoded) > 50 else text
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
                'type': 'vmess', 'server': data.get('add'),
                'port': int(data.get('port', 0)), 'uuid': data.get('id', ''),
                'alterId': int(data.get('aid', 0)), 'cipher': 'auto',
                'tls': data.get('tls') == 'tls', 'network': data.get('net', 'tcp'), 'udp': True
            }
        elif scheme == 'trojan':
            password, rest2 = rest.split('@', 1)
            host_port, params_name = rest2.split('?', 1) if '?' in rest2 else (rest2, '')
            host, port = host_port.split(':', 1)
            name = unquote(params_name.split('#', 1)[1]) if '#' in params_name else f"Trojan-{host}"
            return {'name': name, 'type': 'trojan', 'server': host, 'port': int(port), 'password': password, 'udp': True}
        elif scheme == 'vless':
            uuid, rest2 = rest.split('@', 1)
            host_port, params_name = rest2.split('?', 1) if '?' in rest2 else (rest2, '')
            host, port = host_port.split(':', 1)
            name = unquote(params_name.split('#', 1)[1]) if '#' in params_name else f"VLESS-{host}"
            query = parse_qs(params_name.split('#')[0]) if '?' in params_name else {}
            net = query.get('type', ['tcp'])[0]
            p = {'name': name, 'type': 'vless', 'server': host, 'port': int(port), 'uuid': uuid, 'network': net, 'udp': True, 'tls': query.get('security', [''])[0] in ['tls', 'reality']}
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
                    return {'name': f"SS-{host}", 'type': 'ss', 'server': host, 'port': int(port.split('#')[0]), 'cipher': cipher, 'password': password, 'udp': True}
        elif scheme in ['hysteria', 'hysteria2', 'hy2']:
            auth_rest, params_name = rest.split('?', 1) if '?' in rest else (rest, '')
            if '@' in auth_rest:
                password, host_port = auth_rest.split('@', 1)
            else:
                password, host_port = '', auth_rest
            if ':' in host_port:
                host, port = host_port.split(':', 1)
                name = unquote(params_name.split('#', 1)[1]) if '#' in params_name else f"Hysteria-{host}"
                return {'name': name, 'type': 'hysteria2' if scheme == 'hy2' else scheme, 'server': host, 'port': int(port), 'password': password, 'udp': True}
    except Exception:
        pass
    return None

def is_public_channel(src):
    """Проверяет, является ли канал публичным (можно парсить через web preview)"""
    # Группы/чаты обычно имеют названия в нижнем регистре или специфические паттерны
    # Но надёжнее — попробовать web preview и если не сработал, использовать Telethon
    # Для простоты: считаем, что LowiKForum - это чат
    chat_indicators = ['lowikforum', 'forum', 'chat', 'flood', 'talk']
    return not any(ind in src.lower() for ind in chat_indicators)

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
    
    # Разделяем источники на "публичные" и "приватные/чаты"
    web_sources = []
    telethon_sources = []
    
    for src in sources:
        if not src.startswith('http'):
            continue
        if src.startswith('https://t.me/'):
            # Эвристика: LowiKForum и подобные - это чаты
            if 'LowiKForum' in src or '/c/' in src:  # /c/ - приватные каналы
                telethon_sources.append(src)
            else:
                web_sources.append(src)
        else:
            sub_urls.add(clean_url(src))
    
    print(f"[{time.time()-start_time:.1f}s] Источников: Web={len(web_sources)}, Telethon={len(telethon_sources)}")
    
    # === WEB PREVIEW ПАРСИНГ ===
    if web_sources:
        async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
            print(f"[{time.time()-start_time:.1f}s] Парсим через Web Preview...")
            
            source_tasks = []
            for src in web_sources:
                if re.search(r'/\d+$', src):
                    web_url = f"{src}?embed=1&mode=tme"
                else:
                    web_url = src.replace('https://t.me/', 'https://t.me/s/')
                source_tasks.append((web_url, fetch(session, web_url, http_sem)))
            
            results = await asyncio.gather(*[t[1] for t in source_tasks])
            
            for (url, _), html in zip(source_tasks, results):
                if html:
                    p, u = extract_messages_data(html, cutoff_date)
                    debug_log(f"Из {url[:60]}: {len(p)} прокси, {len(u)} URL подписок")
                    all_proxies.extend(p)
                    for link in u:
                        sub_urls.add(clean_url(link))
            
            # Обрабатываем подписки
            sub_tasks = [process_subscription(url, session, http_sem, visited_subs) for url in sub_urls]
            sub_results = await asyncio.gather(*sub_tasks)
            for res in sub_results:
                all_proxies.extend(res)
    
    # === TELETHON ПАРСИНГ (для чатов) ===
    if telethon_sources and TELETHON_AVAILABLE and API_ID != 0:
        print(f"[{time.time()-start_time:.1f}s] Парсим через Telethon (MTProto)...")
        for src in telethon_sources:
            p, u = await parse_with_telethon(src, cutoff_date)
            all_proxies.extend(p)
            for link in u:
                sub_urls.add(clean_url(link))
            
            # Также обрабатываем найденные подписки
            async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
                for link in u:
                    proxies_from_sub = await process_subscription(link, session, http_sem, visited_subs)
                    all_proxies.extend(proxies_from_sub)
    elif telethon_sources:
        debug_log(f"Telethon не настроен, пропускаем {len(telethon_sources)} источников")
    
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
    
    # Сохранение в proxy.txt (plain text)
    alive_uris = [uri for uri, _ in alive_proxies]
    all_uris = alive_uris + happ_links
    
    update_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    header = [
        f"# Обновлено: {update_time}",
        f"# Живых серверов: {len(alive_uris)}",
        f"# Happ ссылок: {len(happ_links)}",
        f"# Всего ссылок: {len(all_uris)}",
        "#"
    ]
    
    raw_txt = "\n".join(header + all_uris)
    with open(OUT_TXT, 'w', encoding='utf-8') as f:
        f.write(raw_txt)
    
    # Сохранение в proxy.yaml (Clash)
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
            {'name': '♻️ Auto', 'type': 'url-test', 'proxies': proxy_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
            {'name': '🚀 Proxy', 'type': 'select', 'proxies': ['♻️ Auto'] + proxy_names}
        ],
        'rules': ['MATCH,🚀 Proxy']
    }
    
    with open(OUT_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, sort_keys=False, allow_unicode=True)
    
    print(f"✅ Готово за {time.time()-start_time:.1f} секунд!")
    print(f"📄 Файлы обновлены: {OUT_TXT}, {OUT_YAML}")

if __name__ == '__main__':
    asyncio.run(main())
