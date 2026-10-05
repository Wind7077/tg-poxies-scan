import os
import re
import base64
import asyncio
import requests
import yaml
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote
import json

# --- КОНФИГУРАЦИЯ ---
SOURCES_FILE = 'sources.txt'
OUT_TXT = 'proxy.txt'
OUT_YAML = 'proxy.yaml'
MAX_DAYS = 10
TIMEOUT_PING = 3.0

# Регулярки для поиска
PROXY_REGEX = re.compile(r'(vless|vmess|trojan|ss|hysteria2?|hy2|tuic|happ)://[^\s<>"\']+', re.IGNORECASE)
URL_REGEX = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)

def decode_base64(s):
    s = s.replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding: s += '=' * (4 - padding)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def fetch_content(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        return resp.text
    except Exception as e:
        # print(f"Ошибка загрузки {url}: {e}")
        return ""

def extract_from_message(msg_element):
    """Извлекает ссылки и прокси из HTML элемента сообщения Telegram"""
    proxies = []
    urls = []
    
    # 1. Ищем все <a href="..."> (надежный способ для Telegram Web)
    if hasattr(msg_element, 'find_all'):
        for a in msg_element.find_all('a', href=True):
            href = a['href']
            if href.startswith(('vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria', 'tuic://', 'happ://')):
                proxies.append(href)
            elif href.startswith('http'):
                urls.append(href)
            
    # 2. Ищем в самом тексте сообщения (на случай если ссылки просто вставлены текстом)
    text_div = msg_element.find('div', class_='tgme_widget_message_text') if hasattr(msg_element, 'find') else None
    text = text_div.get_text() if text_div else msg_element.get_text()
    
    found_proxies = PROXY_REGEX.findall(text)
    proxies.extend(found_proxies)
    
    found_urls = URL_REGEX.findall(text)
    for u in found_urls:
        # Исключаем ссылки на сам Telegram и системные
        if 't.me' not in u and 'telegram.org' not in u and 'telegram.me' not in u and 'telegra.ph' not in u:
            urls.append(u)
            
    return list(set(proxies)), list(set(urls))

def extract_from_channel(html):
    """Парсит страницу канала t.me/s/channel и собирает посты за последние 10 дней"""
    soup = BeautifulSoup(html, 'html.parser')
    messages = soup.find_all('div', class_='tgme_widget_message')
    
    all_proxies = []
    all_urls = []
    
    for msg in messages:
        # Проверка даты для канала
        time_tag = msg.find('time')
        if time_tag and time_tag.get('datetime'):
            try:
                post_time = datetime.fromisoformat(time_tag['datetime'].replace('Z', '+00:00'))
                if (datetime.now(timezone.utc) - post_time).days > MAX_DAYS:
                    continue # Пропускаем старые посты
            except:
                pass
                
        proxies, urls = extract_from_message(msg)
        all_proxies.extend(proxies)
        all_urls.extend(urls)
        
    return all_proxies, all_urls

def extract_from_html(html):
    """Парсит embed HTML конкретного поста (без проверки даты, так как это может быть обновляемый закреп)"""
    soup = BeautifulSoup(html, 'html.parser')
    msg = soup.find('div', class_='tgme_widget_message')
    if not msg: msg = soup
    return extract_from_message(msg)

def fetch_and_parse_subscription(url):
    """Скачивает подписку (txt/sub) и достает из нее прокси"""
    try:
        if url.startswith('happ://'):
            return [url] # Deep link, сохраняем как есть
            
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        resp = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        text = resp.text
        
        proxies = []
        
        # 1. Пробуем Base64 декодировать весь текст (часто подписки заворачивают в base64)
        decoded = decode_base64(text.strip())
        if decoded and len(decoded) > 10 and PROXY_REGEX.search(decoded):
            text = decoded
            
        # 2. Ищем все прокси
        found = PROXY_REGEX.findall(text)
        proxies.extend(found)
        
        # 3. Рекурсия 1 уровня: если внутри подписки есть ссылки на другие подписки
        found_urls = URL_REGEX.findall(text)
        for sub_url in found_urls:
            if sub_url.startswith('http') and 't.me' not in sub_url and 'telegram' not in sub_url:
                try:
                    sub_resp = requests.get(sub_url, headers=headers, timeout=5)
                    sub_text = sub_resp.text
                    sub_decoded = decode_base64(sub_text.strip())
                    if sub_decoded and PROXY_REGEX.search(sub_decoded):
                        sub_text = sub_decoded
                    proxies.extend(PROXY_REGEX.findall(sub_text))
                except:
                    pass
                    
        return list(set(proxies))
    except Exception:
        return []

async def check_proxy_tcp(host, port):
    """Быстрый TCP пинг"""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TIMEOUT_PING)
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
        
        if scheme == 'happ':
            return None # Clash не поддерживает happ://
            
        if scheme == 'vmess':
            data = json.loads(decode_base64(rest))
            return {
                'name': data.get('ps', f"VMess-{data.get('add')}"),
                'type': 'vmess', 'server': data.get('add'),
                'port': int(data.get('port')), 'uuid': data.get('id'),
                'alterId': int(data.get('aid', 0)), 'cipher': 'auto',
                'tls': data.get('tls') == 'tls', 'network': data.get('net', 'tcp'),
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
                    return {'name': f"SS-{host}", 'type': 'ss', 'server': host, 'port': int(port.split('#')[0]), 'cipher': cipher, 'password': password}
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
                # Конкретный пост (возможно, обновляемый закреп)
                url = f"{src}?embed=1&mode=tme"
                html = fetch_content(url)
                if html:
                    proxies, urls = extract_from_html(html)
                    all_proxies.extend(proxies)
                    for u in urls: all_proxies.extend(fetch_and_parse_subscription(u))
            else:
                # Весь канал (с проверкой даты 10 дней)
                url = src.replace('https://t.me/', 'https://t.me/s/')
                html = fetch_content(url)
                if html:
                    proxies, urls = extract_from_channel(html)
                    all_proxies.extend(proxies)
                    for u in urls: all_proxies.extend(fetch_and_parse_subscription(u))
        else:
            # Прямая ссылка на подписку
            all_proxies.extend(fetch_and_parse_subscription(src))

    # Уникализация и очистка
    all_proxies = [p for p in set(all_proxies) if p and '://' in p]
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
    all_uris = alive_uris + happ_links # Добавляем happ:// ссылки
    
    raw_txt = "\n".join(all_uris)
    b64_txt = base64.b64encode(raw_txt.encode('utf-8')).decode('utf-8')
    with open(OUT_TXT, 'w', encoding='utf-8') as f:
        f.write(b64_txt)
        
    # --- Сохранение в proxy.yaml (Clash Meta / Clash) ---
    clash_proxies = [p for _, p in alive_proxies] # Только те, что понимает Clash
    
    clash_config = {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'Rule', 'log-level': 'info',
        'external-controller': '127.0.0.1:9090', 'proxies': clash_proxies,
        'proxy-groups': [
            {'name': '♻️ Auto', 'type': 'url-test', 'proxies': [p['name'] for p in clash_proxies] if clash_proxies else ['DIRECT'], 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
            {'name': '🚀 Proxy', 'type': 'select', 'proxies': ['♻️ Auto'] + [p['name'] for p in clash_proxies] if clash_proxies else ['DIRECT']}
        ],
        'rules': ['MATCH,🚀 Proxy']
    }
    
    with open(OUT_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, sort_keys=False, allow_unicode=True)

if __name__ == '__main__':
    asyncio.run(main())
