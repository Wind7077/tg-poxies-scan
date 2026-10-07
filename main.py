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
