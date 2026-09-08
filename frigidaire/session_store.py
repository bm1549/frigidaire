"""Persistence for the session key so a still-valid token survives process restarts.

Abandoning a valid session and minting a new one on every start leaves sessions lingering
server-side until Electrolux's active-session cap (``cas_3403``) locks the account out.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Protocol

_LOGGER = logging.getLogger(__name__)


class SessionStore(Protocol):
    def load(self) -> tuple[str | None, str | None]:
        """Return the stored ``(session_key, regional_base_url)``, or ``(None, None)``."""

    def save(self, session_key: str, regional_base_url: str | None) -> None:
        """Persist the session the client is currently using."""


class JsonFileSessionStore:
    """Stores the session in a small JSON file. Writes are serialised across threads."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()

    def load(self) -> tuple[str | None, str | None]:
        try:
            with open(self._path) as f:
                text = f.read()
        except FileNotFoundError:
            return None, None
        if not text.strip():
            return None, None
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            _LOGGER.warning("Ignoring unreadable session file %s", self._path)
            return None, None
        return obj.get("session_key"), obj.get("regional_base_url")

    def save(self, session_key: str, regional_base_url: str | None) -> None:
        with self._lock, open(self._path, "w") as f:
            json.dump({"session_key": session_key, "regional_base_url": regional_base_url}, f, indent=4)
