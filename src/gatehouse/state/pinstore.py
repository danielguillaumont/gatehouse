"""Persistent pin store shared by every gatehouse wrapper on the machine.

File format (JSON, version 1)::

    {"version": 1,
     "servers": {"<server name>": {"tools": {"<tool name>": {
         "sha256": "...", "pinned_at": "...", "pinned_by": "pin|tofu",
         "definition": {...pinned view...}}}}}}

Writes take an exclusive lock file and replace the store atomically, so concurrent
wrappers (TOFU) and ``gatehouse pin`` can't corrupt it.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from gatehouse.inspect.pinning import pinned_view, tool_digest

MAX_STORE_BYTES = 32 * 1024 * 1024
LOCK_TIMEOUT_S = 10.0
LOCK_STALE_S = 30.0


class PinStoreError(Exception):
    """The pin store exists but cannot be trusted (unreadable, corrupt, wrong version)."""


class ToolPin(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pinned_at: datetime
    pinned_by: Literal["pin", "tofu"]
    definition: dict[str, Any]


class ServerPins(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tools: dict[str, ToolPin] = Field(default_factory=dict[str, ToolPin])


class PinStore(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    servers: dict[str, ServerPins] = Field(default_factory=dict[str, ServerPins])

    def server(self, name: str) -> ServerPins:
        return self.servers.get(name, ServerPins())


def load_pins(path: Path) -> PinStore:
    """Load the store. A missing file is an empty store; anything else wrong raises."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_STORE_BYTES + 1)
    except FileNotFoundError:
        return PinStore()
    except OSError as exc:
        raise PinStoreError(f"cannot read pin store {path}: {exc.strerror or exc}") from None
    if len(data) > MAX_STORE_BYTES:
        raise PinStoreError(f"pin store {path} exceeds {MAX_STORE_BYTES} bytes")
    try:
        return PinStore.model_validate_json(data)
    except ValidationError as exc:
        raise PinStoreError(f"pin store {path} is invalid: {exc.error_count()} error(s)") from None


@contextmanager
def _locked(path: Path) -> Generator[None]:
    lock = path.with_name(path.name + ".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + LOCK_TIMEOUT_S
    last: OSError | None = None
    while True:
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            break
        except FileExistsError as exc:
            last = exc
            try:
                if time.time() - lock.stat().st_mtime > LOCK_STALE_S:
                    lock.unlink(missing_ok=True)  # holder crashed
                    continue
            except (FileNotFoundError, PermissionError):
                continue
        except PermissionError as exc:
            # Windows: creating a file that another process/thread is deleting fails with
            # "access denied" (delete pending), not "exists". That is contention: retry.
            # A genuinely unwritable directory ends in the timeout below, with the cause.
            if sys.platform != "win32":
                raise PinStoreError(f"cannot create pin store lock {lock}: {exc}") from None
            last = exc
        if time.monotonic() > deadline:
            raise PinStoreError(
                f"timed out waiting for pin store lock {lock} (last error: {last})"
            ) from None
        time.sleep(0.02)
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def _atomic_write(path: Path, payload: str) -> None:
    tmp = path.with_name(f"{path.name}.tmp{os.getpid()}")
    tmp.write_text(payload, encoding="utf-8", newline="\n")
    for attempt in range(50):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:  # Windows: a reader has the file open
            if attempt == 49:
                tmp.unlink(missing_ok=True)
                raise
            time.sleep(0.02)


def save_pins(path: Path, store: PinStore) -> None:
    with _locked(path):
        _atomic_write(path, store.model_dump_json(indent=2) + "\n")


def pin_tools(
    path: Path,
    server: str,
    tools: Mapping[str, Mapping[str, Any]],
    *,
    pinned_by: Literal["pin", "tofu"],
    replace_server: bool = False,
    only_new: bool = False,
) -> PinStore:
    """Pin ``tools`` (name -> definition) for ``server`` under the store lock.

    ``replace_server``: drop pins for tools not in ``tools`` (``gatehouse pin``).
    ``only_new``: never overwrite an existing pin (TOFU must not "re-trust" a change).
    """
    with _locked(path):
        store = load_pins(path)
        current: dict[str, ToolPin] = {} if replace_server else dict(store.server(server).tools)
        now = datetime.now(UTC)
        for name, definition in tools.items():
            if only_new and name in store.server(server).tools:
                continue
            current[name] = ToolPin(
                sha256=tool_digest(definition),
                pinned_at=now,
                pinned_by=pinned_by,
                definition=pinned_view(definition),
            )
        servers = dict(store.servers)
        servers[server] = ServerPins(tools=current)
        updated = PinStore(servers=servers)
        _atomic_write(path, json.dumps(updated.model_dump(mode="json"), indent=2) + "\n")
        return updated
