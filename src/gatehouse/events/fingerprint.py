"""Keyed fingerprints (HMAC-SHA256) for values that must never be logged.

A plain SHA-256 of a secret lets anyone holding the logs confirm a guessed secret
offline. HMAC with a per-install key keeps fingerprints useful for correlation inside
one deployment ("the same token appeared in three sessions") without that property.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

from gatehouse.canonical import canonical_json

KEY_BYTES = 32


def load_or_create_key(path: Path, attempts: int = 50) -> bytes:
    """Read the install key, creating it (owner-only permissions) on first use.

    Several wrappers may start at once: creation uses O_EXCL so exactly one writes the
    key, and readers retry briefly while it is being written.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(attempts):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
        except FileExistsError:
            key = path.read_bytes()
            if len(key) == KEY_BYTES:
                return key
            if len(key) > KEY_BYTES:
                raise ValueError(f"corrupt HMAC key file {path}") from None
            time.sleep(0.02)  # being written by another process
            continue
        key = secrets.token_bytes(KEY_BYTES)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        return key
    raise TimeoutError(f"HMAC key file {path} stayed incomplete")


_O_BINARY = getattr(os, "O_BINARY", 0)


class Fingerprinter:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def text(self, value: str) -> str:
        return hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def json(self, value: object) -> str:
        return self.text(canonical_json(value))

    def __call__(self, value: str) -> str:
        return self.text(value)
