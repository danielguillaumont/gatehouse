"""Policy-file integrity: detect on-disk changes while a session is running.

The running process keeps the policy it loaded at startup (no hot reload), so a changed
file never weakens an active session; the change is reported as ``policy.tampered``.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from gatehouse.policy.loader import MAX_POLICY_BYTES


class PolicyWatcher:
    def __init__(self, path: Path, loaded_sha256: str | None) -> None:
        self.path = path
        self.loaded_sha256 = loaded_sha256
        self._last_stat: tuple[int, int] | None = self._stat()
        self.reported = False

    def _stat(self) -> tuple[int, int] | None:
        try:
            st = os.stat(self.path)
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def current_sha256(self) -> str | None:
        try:
            with open(self.path, "rb") as fh:
                data = fh.read(MAX_POLICY_BYTES + 1)
        except OSError:
            return None
        return hashlib.sha256(data).hexdigest()

    def changed(self) -> tuple[bool, str | None]:
        """Return (changed, current_hash). Cheap stat check first; hash only on change."""
        st = self._stat()
        if st == self._last_stat:
            return False, self.loaded_sha256
        self._last_stat = st
        current = self.current_sha256()
        return current != self.loaded_sha256, current
