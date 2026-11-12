import os
print("="*40)
print("ДИАГНОСТИКА СЕКРЕТОВ TELETHON:")
api_id = os.getenv('TELEGRAM_API_ID', '')
api_hash = os.getenv('TELEGRAM_API_HASH', '')
session = os.getenv('TELEGRAM_SESSION', '')
print(f"API_ID: {'✅ Есть (' + str(len(api_id)) + ' симв)' if api_id else '❌ ПУСТО (не передан)'}")
print(f"API_HASH: {'✅ Есть (' + str(len(api_hash)) + ' симв)' if api_hash else '❌ ПУСТО (не передан)'}")
print(f"SESSION: {'✅ Есть (' + str(len(session)) + ' симв)' if session else '❌ ПУСТО (не передан)'}")
print("="*40)

import asyncio
import sys
from scanner.pipeline import run

if __name__ == '__main__':
    sys.exit(asyncio.run(run('config.yaml')))
