"""Put the repo root on sys.path so tests can `import engine` without an install."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
