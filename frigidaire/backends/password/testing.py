"""``FakeFrigidaire``: the synchronous client with no HTTP, for downstream test suites.

Import it from :mod:`frigidaire.testing`, where it has always been. It lives here because it is
the sync password client, and goes when this package does.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any, TypeVar

from ...model import Appliance, Component
from .session_store import SessionStore
from .sync_client import Frigidaire

T = TypeVar("T")


class FakeFrigidaire(Frigidaire):
    """A ``Frigidaire`` with no HTTP: canned records in, recorded commands out.

    It replaces only the transport, so the real command plans and parsing run unchanged.
    ``error`` is raised by the next fetch when set. ``commands`` lists every
    ``(setting, value)`` pair sent, in order. ``fetch_count`` counts appliance-list fetch
    attempts, failed ones included.
    """

    def __init__(
        self,
        records: list[dict],
        username: str = "user@example.com",
        password: str = "secret",
        *,
        session_store: SessionStore | None = None,
        **_ignored: Any,
    ) -> None:
        # Deliberately skips Frigidaire.__init__: no requests session, no authentication.
        self.username = username
        self.password = password
        self.session_key: str | None = "fake-session-key"
        self.regional_base_url: str | None = "https://api.us.ocp.electrolux.one"
        self._session_store = session_store
        self.records: dict[str, dict] = {r["applianceId"]: copy.deepcopy(r) for r in records}
        self.commands: list[tuple[str, Any]] = []
        self.error: Exception | None = None
        self.fetch_count = 0
        self._persist_session()

    def _with_reauth(self, fn: Callable[[], T]) -> T:
        return fn()

    def _fetch_raw_appliances(self) -> list[dict]:
        self.fetch_count += 1  # counts attempts, so callers can assert on backoff
        if self.error is not None:
            raise self.error
        return [copy.deepcopy(record) for record in self.records.values()]

    def execute_action(self, appliance: Appliance, action: list[Component]) -> None:
        self.commands.extend((component.name, component.value) for component in action)
