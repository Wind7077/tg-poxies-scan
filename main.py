import asyncio
import sys

from scanner.pipeline import run

if __name__ == '__main__':
    sys.exit(asyncio.run(run()))
