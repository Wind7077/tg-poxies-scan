import os
import re
import base64
import asyncio
import requests
import yaml
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs, unquote
import json

# --- КОНФИГУРАЦИЯ ---
SOURCES_FILE = 'sources.txt'
OUT_TXT = 'proxy.txt'
OUT_YAML = 'proxy.yaml'
MAX_DAYS = 10
TIMEOUT_PING = 3.0

# Регулярки для поиска
PROXY_REGEX = re.compile(r'(vless|vmess|trojan|ss|hysteria2?|tuic)://[^\s<"\']+', re.IGNORECASE)
URL_REGEX = re.compile(r'https?://[^\s<"\']+', re.IGNORECASE)

def decode_base64(s):
    """Безопасное декодирование base64 (с учетом URL-safe вариантов)"""
    s = s.replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding: s += '=' * (4 - padding)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def normalize_url(url):
    """Преобразует ссылку на пост/канал в формат для удобного парсинга"""
    url = url.strip()
    if url.startswith('https://t.me/') and not url.startswith('https://t.me/s/'):
        if '?' in url: url = url.split('?')[0]
        # Для постов используем embed режим, для каналов добавляем /s/
        if re.search(r'/\d+$', url):
            return f"{url}?embed=1&mode=tme"
        else:
            return url.replace('https://t.me/', 'https://t.me/s/')
    return url

def fetch_content(url):
    """Скачивает HTML страницы"""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        return resp.text
    except Exception as e:
        print(f"Ошибка загрузки {url}: {e}")
        return ""

def parse_date(html):
    """Проверяет, не старше ли пост 10 дней (для embed-постов)"""
    soup = BeautifulSoup(html, 'html.parser')
    time_tag = soup.find('time')
    if time_tag and time_tag.get('datetime'):
        try:
            post_time = datetime.fromisoformat(time_tag['datetime'].replace('Z', '+00:00'))
            if (datetime.now(timezone.utc) - post_time).days > MAX_DAYS:
                return False # Старый пост
        except:
            pass
    return True

def extract_data(html):
    """Достает ссылки и raw прокси из HTML"""
    proxies = []
    urls = []
    
    # Ищем сырые ссылки
    proxies.extend(PROXY_REGEX.findall(html))
    
    # Ищем URL подписок
    found_urls = URL_REGEX.findall(html)
    for u in found_urls:
        if 't.me' not in u and 'telegram' not in u: # Исключаем ссылки на сам телеграм
            urls.append(u)
            
    return list(set(proxies)), list(set(urls))

async def check_proxy_tcp(host, port):
    """Асинхронный TCP пинг"""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TIMEOUT_PING)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

def parse_uri(uri):
    """Парсит URI в словарь для Clash YAML"""
    try:
        scheme, rest = uri.split('://', 1)
        scheme = scheme.lower()
        
        if scheme == 'vmess':
            data = json.loads(decode_base64(rest))
            return {
                'name': data.get('ps', f"VMess-{data.get('add')}"),
                'type': 'vmess',
                'server': data.get('add'),
                'port': int(data.get('port')),
                'uuid': data.get('id'),
                'alterId': int(data.get('aid', 0)),
                'cipher': 'auto',
                'tls': data.get('tls') == 'tls',
                'network': data.get('net', 'tcp'),
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
                'name': name, 'type': 'vless', 'server': host, 'port': int(port),
                'uuid': uuid, 'network': net, 'udp': True,
                'tls': query.get('security', [''])[0] in ['tls', 'reality']
            }
            if net == 'ws':
                p['ws-opts'] = {'path': unquote(query.get('path', ['/'])[0])}
            return p
            
        elif scheme == 'ss':
            # Базовый парсер SS (метод:пароль@хост:порт)
            if '@' in rest:
                userinfo, hostport = rest.split('@', 1)
                if ':' in hostport:
                    host, port = hostport.split(':', 1)
                    if ':' in userinfo: cipher, password = userinfo.split(':', 1)
                    else: cipher, password = 'aes-256-gcm', decode_base64(userinfo)
                    return {'name': f"SS-{host}", 'type': 'ss', 'server': host, 'port': int(port.split('#')[0]), 'cipher': cipher, 'password': password}
    except Exception as e:
        # print(f"Ошибка парсинга {uri}: {e}")
        pass
    return None

async def main():
    if not os.path.exists(SOURCES_FILE):
        print("Файл sources.txt не найден!")
        return

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    all_proxies = []
    
    print(f"Начинаем оббор {len(sources)} источников...")
    for src in sources:
        url = normalize_url(src)
        html = fetch_content(url)
        if not html: continue
        
        # Проверка даты для одиночных постов
        if '?embed=1' in url and not parse_date(html):
            print(f"Пропускаем {src} (старше {MAX_DAYS} дней)")
            continue
            
        proxies, sub_urls = extract_data(html)
        all_proxies.extend(proxies)
        
        # Обработка ссылок-подписок
        for sub_url in sub_urls:
            try:
                sub_text = requests.get(sub_url, timeout=10).text
                # Если это base64
                decoded = decode_base64(sub_text)
                if decoded: sub_text = decoded
                all_proxies.extend(PROXY_REGEX.findall(sub_text))
            except:
                pass

    # Уникализация
    all_proxies = list(set(all_proxies))
    print(f"Найдено сырых ссылок: {len(all_proxies)}")

    # Пинг и проверка
    print("Проверяем доступность серверов (TCP Ping)...")
    alive_proxies = []
    
    tasks = []
    proxy_map = {} # Для сохранения оригинального URI
    
    for uri in all_proxies:
        parsed = parse_uri(uri)
        if parsed and parsed.get('server') and parsed.get('port'):
            tasks.append(check_proxy_tcp(parsed['server'], parsed['port']))
            proxy_map[len(tasks)-1] = (uri, parsed)
            
    results = await asyncio.gather(*tasks)
    
    for i, is_alive in enumerate(results):
        if is_alive:
            alive_proxies.append(proxy_map[i])
            
    print(f"Живых серверов: {len(alive_proxies)}")

    # Сохранение в proxy.txt (Base64 для V2Ray/NekoBox)
    raw_txt = "\n".join([uri for uri, _ in alive_proxies])
    b64_txt = base64.b64encode(raw_txt.encode('utf-8')).decode('utf-8')
    with open(OUT_TXT, 'w', encoding='utf-8') as f:
        f.write(b64_txt)
        
    # Сохранение в proxy.yaml (Clash Meta / Clash)
    clash_config = {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'Rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': [p for _, p in alive_proxies],
        'proxy-groups': [
            {
                'name': '♻️ Auto',
                'type': 'url-test',
                'proxies': [p['name'] for _, p in alive_proxies],
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300
            },
            {
                'name': '🚀 Proxy',
                'type': 'select',
                'proxies': ['♻️ Auto'] + [p['name'] for _, p in alive_proxies]
            }
        ],
        'rules': [
            'MATCH,🚀 Proxy'
        ]
    }
    
    with open(OUT_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, sort_keys=False, allow_unicode=True)

if __name__ == '__main__':
    asyncio.run(main())
