"""Notice that the engine's code changed after the server started.

Jinja reloads templates from disk on every render; the Python that builds their
context does not. So a server left running while the engine is edited keeps
answering with the old logic, and nothing says so. That is the dangerous case:
not the crash, which announces itself, but a run that completes normally and
reports numbers produced by code that has since been replaced. Those numbers end
up in a SOW.

Only `.py` files under `engine/` are watched. Templates reload by themselves, and
static assets are read from disk per request, so neither goes stale in this sense.
"""

from __future__ import annotations

import time
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parents[1]

# The status page polls every second. Re-walking the tree that often is cheap but
# pointless; nobody edits the engine twice in two seconds.
RECHECK_SECONDS = 2.0


class StalenessWatch:
    """Compares the engine's code now against what it was at startup."""

    def __init__(self, directory: Path | None = None, recheck_seconds: float = RECHECK_SECONDS):
        self.directory = directory or ENGINE_DIR
        self.recheck_seconds = recheck_seconds
        self._started_with: str | None = None
        self._checked_at: float = 0.0
        self._stale: bool = False

    def mark_started(self) -> None:
        """Record the code as it is now. Called when the app is built."""
        self._started_with = self.fingerprint()
        self._checked_at = time.monotonic()
        self._stale = False

    def fingerprint(self) -> str:
        """How many Python files there are under the directory, and the newest mtime."""
        newest = 0.0
        count = 0
        for path in self.directory.rglob("*.py"):
            count += 1
            try:
                newest = max(newest, path.stat().st_mtime)
            except OSError:
                continue
        return f"{count}:{newest:.3f}"

    def is_stale(self) -> bool:
        """True when the code on disk differs from the code this process loaded."""
        if self._started_with is None:
            # Never marked, so there is nothing to compare against. Saying "stale"
            # here would put a warning on every page of a correctly running server.
            return False

        now = time.monotonic()
        if now - self._checked_at < self.recheck_seconds:
            return self._stale

        self._checked_at = now
        self._stale = self.fingerprint() != self._started_with
        return self._stale


watch = StalenessWatch()
