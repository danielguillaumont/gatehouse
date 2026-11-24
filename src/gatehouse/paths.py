"""Where gatehouse keeps local state (pins, HMAC key, event logs)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ENV_HOME = "GATEHOUSE_HOME"


def state_dir() -> Path:
    """Per-user state directory. Override with $GATEHOUSE_HOME.

    Windows: %LOCALAPPDATA%\\gatehouse. Elsewhere: $XDG_STATE_HOME/gatehouse or
    ~/.local/state/gatehouse.
    """
    override = os.environ.get(ENV_HOME)
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "gatehouse"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "gatehouse"


def default_pins_path() -> Path:
    return state_dir() / "pins.json"


def default_events_dir() -> Path:
    return state_dir() / "events"


def default_hmac_key_path() -> Path:
    return state_dir() / "hmac.key"
