import os
import sys

# Ensure the repository root is importable so tests can do `from scanner import ...`
# regardless of how pytest is invoked (e.g. `pytest -q tests`).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
