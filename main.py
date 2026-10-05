import os
import re
import base64
import asyncio
import requests
import yaml
import json
from bs4 import BeautifulSoup
from datetime import datetime, timezone, timedelta
from urllib.parse import parse_qs, unquote

# --- КОНФИГУРАЦИЯ ---
SOURCES_FILE = 'sources.txt'
OUT_TXT = 'proxy.txt'
OUT_YAML = 'proxy.yaml'
MAX_DAYS = 10
TIMEOUT_REQ = 10
TIMEOUT_PING = 3.0

# Поддерживаемые схемы
PROXY_SCHEMES = ['vless', 'vmess', 'ss', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'happ']
PROXY_REGEX = re.compile(r'(' + '|'.join(PROXY_SCHEMES) + r')://[^\s<>"\'`]+', re.IGNORECASE)
URL_REGEX = re.compile(r'https?://[^\s<>"\'`]+', re.IGNORECASE)

# Кэш посещенных URL подписок, чтобы не ходить по кругу
visited_subs = set()

def decode_base64(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding: s += '=' * (4 - padding)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def fetch_content(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT_REQ, allow_redirects=True)
        return resp.text
    except Exception:
        return ""

def extract_from_element(element):
    """Извлекает прокси и URL подписок из HTML элемента сообщения"""
    proxies = []
    urls = []
    
    # 1. Ищем гиперссылки <a href="...">
    if hasattr(element, 'find_all'):
        for a in element.find_all('a', href=True):
            href = a['href']
            if href.startswith(tuple(f"{s}://" for s in PROXY_SCHEMES)):
                proxies.append(href)
            elif href.startswith('http') and 't.me' not in href and 'telegram' not in href:
                urls.append(href)
                
    # 2. Ищем в самом тексте сообщения (на случай если ссылки просто вставлены текстом)
    text = element.get_text() if hasattr(element, 'get_text') else str(element)
    proxies.extend(PROXY_REGEX.findall(text))
    
    found_urls = URL_REGEX.findall(text)
    for u in found_urls:
        # Исключаем ссылки на сам Telegram
        if not any(d in u for d in ['t.me', 'telegram.org', 'telegram.me', 'telegra.ph']):
            urls.append(u)
            
    return list(set(proxies)), list(set(urls))

def extract_from_channel(html):
    """Парсит страницу канала t.me/s/channel (с проверкой даты 10 дней)"""
    soup = BeautifulSoup(html, 'html.parser')
    messages = soup.find_all('div', class_='tgme_widget_message')
    
    all_proxies, all_urls = [], []
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=MAX_DAYS)
    
    for msg in messages:
        time_tag = msg.find('time')
        if time_tag and time_tag.get('datetime'):
            try:
                post_time = datetime.fromisoformat(time_tag['datetime'].replace('Z', '+00:00'))
                if post_time < cutoff_date:
                    continue # Пропускаем старые посты
            except:
                pass
                
        p, u = extract_from_element(msg)
        all_proxies.extend(p)
        all_urls.extend(u)
        
    return all_proxies, all_urls

def extract_from_html(html):
    """Парсит embed HTML конкретного поста (без проверки даты, т.к. это может быть обновляемый закреп)"""
    soup = BeautifulSoup(html, 'html.parser')
    msg = soup.find('div', class_='tgme_widget_message') or soup
    return extract_from_element(msg)

def process_subscription(url):
    """Скачивает подписку, декодирует Base64 и возвращает список прокси"""
    if url in visited_subs: return []
    visited_subs.add(url)
    
    if url.startswith('happ://'): return [url]
    
    text = fetch_content(url)
    if not text: return []
    
    proxies = []
    
    # 1. Пробуем декодировать как Base64 (стандарт для панелей типа 3x-ui)
    decoded = decode_base64(text)
    search_text = decoded if decoded and PROXY_REGEX.search(decoded) else text
    
    # 2. Извлекаем прокси
    proxies.extend(PROXY_REGEX.findall(search_text))
    
    # 3. Рекурсия (1 уровень): если внутри подписки есть ссылки на другие подписки
    found_urls = URL_REGEX.findall(search_text)
    for sub_url in found_urls:
        if sub_url.startswith('http'):
            proxies.extend(process_subscription(sub_url))
            
    return list(set(proxies))

async def check_proxy_tcp(host, port):
    """Быстрый TCP пинг"""
    try:
        port_int = int(port)
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port_int), timeout=TIMEOUT_PING)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

def parse_uri_for_clash(uri):
    """Парсит URI в словарь для Clash YAML. Возвращает None для happ://"""
    try:
        scheme, rest = uri.split('://', 1)
        scheme = scheme.lower()
        
        if scheme == 'happ': return None # Clash не ест happ://
            
        if scheme == 'vmess':
            data = json.loads(decode_base64(rest))
            return {
                'name': data.get('ps', f"VMess-{data.get('add')}"),
                'type': 'vmess', 'server': data.get('add'),
                'port': int(data.get('port', 0)), 'uuid': data.get('id', ''),
                'alterId': int(data.get('aid', 0)), 'cipher': 'auto',
                'tls': data.get('tls') == 'tls', 'network': data.get('net', 'tcp'),
                'udp': True
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
            if net == 'ws': p['ws-opts'] = {'path': unquote(query.get('path', ['/'])[0])}
            return p
        elif scheme == 'ss':
            if '@' in rest:
                userinfo, hostport = rest.split('@', 1)
                if ':' in hostport:
                    host, port = hostport.split(':', 1)
                    if ':' in userinfo: cipher, password = userinfo.split(':', 1)
                    else: cipher, password = 'aes-256-gcm', decode_base64(userinfo)
                    return {'name': f"SS-{host}", 'type': 'ss', 'server': host, 'port': int(port.split('#')[0]), 'cipher': cipher, 'password': password, 'udp': True}
        elif scheme in ['hysteria', 'hysteria2', 'hy2']:
            auth_rest, params_name = rest.split('?', 1) if '?' in rest else (rest, '')
            if '@' in auth_rest: password, host_port = auth_rest.split('@', 1)
            else: password, host_port = '', auth_rest
            if ':' in host_port:
                host, port = host_port.split(':', 1)
                name = unquote(params_name.split('#', 1)[1]) if '#' in params_name else f"Hysteria-{host}"
                return {'name': name, 'type': 'hysteria2' if scheme=='hy2' else scheme, 'server': host, 'port': int(port), 'password': password, 'udp': True}
    except Exception:
        pass
    return None

async def main():
    if not os.path.exists(SOURCES_FILE):
        print("Файл sources.txt не найден!")
        return

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    all_proxies = []
    
    print(f"Начинаем сбор из {len(sources)} источников...")
    for src in sources:
        if not src.startswith('http'): continue
        
        is_specific_post = bool(re.search(r'/\d+$', src))
        
        if src.startswith('https://t.me/') and not src.startswith('https://t.me/s/'):
            if is_specific_post:
                # Конкретный пост (возможно, обновляемый закреп) - дату не проверяем!
                url = f"{src}?embed=1&mode=tme"
                html = fetch_content(url)
                if html:
                    p, u = extract_from_html(html)
                    all_proxies.extend(p)
                    for link in u: all_proxies.extend(process_subscription(link))
            else:
                # Весь канал (с проверкой даты 10 дней)
                url = src.replace('https://t.me/', 'https://t.me/s/')
                html = fetch_content(url)
                if html:
                    p, u = extract_from_channel(html)
                    all_proxies.extend(p)
                    for link in u: all_proxies.extend(process_subscription(link))
        else:
            # Прямая ссылка на подписку (не Telegram)
            all_proxies.extend(process_subscription(src))

    # Уникализация и очистка
    all_proxies = [p.strip() for p in set(all_proxies) if p and '://' in p]
    print(f"Найдено сырых ссылок: {len(all_proxies)}")

    proxies_to_ping = []
    happ_links = []
    
    for uri in all_proxies:
        if uri.lower().startswith('happ://'):
            happ_links.append(uri) # Happ deep links не пингуем TCP-пингом
        else:
            proxies_to_ping.append(uri)

    print(f"Проверяем доступность {len(proxies_to_ping)} серверов (TCP Ping)...")
    alive_proxies = []
    
    tasks = []
    proxy_map = {}
    
    for uri in proxies_to_ping:
        parsed = parse_uri_for_clash(uri)
        if parsed and parsed.get('server') and parsed.get('port'):
            tasks.append(check_proxy_tcp(parsed['server'], parsed['port']))
            proxy_map[len(tasks)-1] = (uri, parsed)
            
    if tasks:
        results = await asyncio.gather(*tasks)
        for i, is_alive in enumerate(results):
            if is_alive:
                alive_proxies.append(proxy_map[i])
            
    print(f"Живых серверов: {len(alive_proxies)}")

    # --- Сохранение в proxy.txt (Base64 для V2Ray / NekoBox / Happ) ---
    alive_uris = [uri for uri, _ in alive_proxies]
    # Складываем чистые живые сервера + happ:// ссылки
    all_uris = alive_uris + happ_links 
    
    raw_txt = "\n".join(all_uris)
    b64_txt = base64.b64encode(raw_txt.encode('utf-8')).decode('utf-8')
    with open(OUT_TXT, 'w', encoding='utf-8') as f:
        f.write(b64_txt)
        
    # --- Сохранение в proxy.yaml (Clash Meta / Clash) ---
    clash_proxies = [p for _, p in alive_proxies] # Только те, что понимает Clash
    
    # Если серверов нет, добавляем DIRECT, чтобы YAML был валидным
    proxy_names = [p['name'] for p in clash_proxies] if clash_proxies else ['DIRECT']
    
    clash_config = {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'Rule', 'log-level': 'info',
        'external-controller': '127.0.0.1:9090', 'proxies': clash_proxies,
        'proxy-groups': [
            {'name': '♻️ Auto', 'type': 'url-test', 'proxies': proxy_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
            {'name': '🚀 Proxy', 'type': 'select', 'proxies': ['♻️ Auto'] + proxy_names}
        ],
        'rules': ['MATCH,🚀 Proxy']
    }
    
    with open(OUT_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, sort_keys=False, allow_unicode=True)

if __name__ == '__main__':
    asyncio.run(main())
