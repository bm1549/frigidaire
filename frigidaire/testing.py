"""In-memory clients and sample records for downstream test suites.

- ``FakeBackend`` implements the :class:`~frigidaire.backends.base.Backend` protocol with no
  network: it serves canned appliance records and records every command instead of sending it,
  so the real client, command plans and parsing run unchanged.
- ``FakeAsyncFrigidaire(records)`` is an :class:`~frigidaire.client.AsyncFrigidaire` on a fresh
  ``FakeBackend``.
- ``FakeFrigidaire(records)`` is the synchronous ``Frigidaire`` with the transport replaced, as in
  1.0. It belongs to the password backend and is imported from there on first use, so this module
  imports no backend.
- ``LEGACY_AC``, ``TELICA_AC`` and ``DEHUMIDIFIER`` are real sample records; ``with_reported``
  varies them.
"""

from __future__ import annotations

import asyncio
import copy
import importlib
from typing import Any

from .backends.base import ConnectionCallback, RecordCallback
from .client import AsyncFrigidaire
from .exceptions import FrigidaireException

# LEGACY_AC uses the uppercase spelling older window units report; TELICA_AC is trimmed
# from a real GHPH142AA1 response and uses the lowercase spelling of newer firmware.

LEGACY_AC: dict = {
    "applianceId": "AC-LEGACY-1",
    "applianceData": {"modelName": "AC", "applianceName": "Bedroom AC"},
    "properties": {
        "reported": {
            "applianceState": "RUNNING",
            "mode": "COOL",
            "fanSpeedSetting": "AUTO",
            "fanSpeedState": "LOW",
            "filterState": "GOOD",
            "sleepMode": "OFF",
            "verticalSwing": "OFF",
            "uiLockMode": False,
            "ambientTemperatureF": 75,
            "targetTemperatureF": 72,
            "temperatureRepresentation": "FAHRENHEIT",
            "startTime": 0,
            "stopTime": 0,
            "alerts": [],
        }
    },
    "status": "enabled",
    "connectionState": "Connected",
}

TELICA_AC: dict = {
    "applianceId": "AC-TELICA-1",
    "applianceData": {"modelName": "Telica", "applianceName": "Office AC"},
    "properties": {
        "reported": {
            "applianceState": "running",
            "mode": "fanOnly",
            "modeState": "fanOnly",
            "fanSpeedSetting": "auto",
            "fanSpeedState": "high",
            "filterState": "good",
            "sleepMode": "off",
            "uiLockMode": False,
            "ambientTemperatureF": 72,
            "targetTemperatureF": 60,
            "temperatureRepresentation": "fahrenheit",
            "sensorHumidity": 86,
            "pm25": 2,
            "pm10": 199,
            "networkInterface": {"linkQualityIndicator": "EXCELLENT", "rssi": -41},
            "alerts": [],
        }
    },
    "status": "enabled",
    "connectionState": "Connected",
}

DEHUMIDIFIER: dict = {
    "applianceId": "DH-1",
    "applianceData": {"modelName": "DH", "applianceName": "Basement Dehumidifier"},
    "properties": {
        "reported": {
            "applianceState": "RUNNING",
            "mode": "DRY",
            "fanSpeedSetting": "LOW",
            "filterState": "GOOD",
            "sensorHumidity": 55,
            "targetHumidity": 45,
            "waterBucketLevel": 0,
            "displayLight": "DISPLAY_LIGHT_1",
            "cleanAirMode": "OFF",
            "uiLockMode": False,
            "alerts": [],
        }
    },
    "status": "enabled",
    "connectionState": "Connected",
}


def with_reported(record: dict, **changes: Any) -> dict:
    """Return a deep copy of ``record`` with ``properties.reported`` keys replaced by ``changes``."""
    updated = copy.deepcopy(record)
    updated["properties"]["reported"].update(changes)
    return updated


class FakeBackend:
    """A backend with no network: canned records in, recorded commands out.

    - ``records`` maps each appliance id to its record. Fetches return deep copies.
    - ``commands`` lists every ``(key, value)`` sent, in order; ``sent`` the same with the
      appliance id first, as ``(appliance_id, key, value)``.
    - ``error``, when set, is raised by ``connect`` and by every fetch until it is cleared.
    - ``command_error``, when set, is raised by every ``send`` until it is cleared; nothing is
      recorded for a rejected command.
    - ``fetch_count`` counts ``fetch_records`` attempts and ``record_fetch_count`` counts
      ``fetch_record`` attempts, failed ones included, so callers can assert on backoff.
    - ``supports_live_updates`` is settable. While it is ``True``, ``listen`` runs until
      cancelled and ``push`` delivers a record to it; while ``False``, ``listen`` raises
      ``NotImplementedError`` like the password backend.
    """

    def __init__(
        self,
        records: list[dict] | None = None,
        *,
        email: str = "user@example.com",
        supports_live_updates: bool = False,
    ) -> None:
        self.records: dict[str, dict] = {r["applianceId"]: copy.deepcopy(r) for r in records or []}
        self.email = email
        self.supports_live_updates = supports_live_updates
        self.commands: list[tuple[str, Any]] = []
        self.sent: list[tuple[str, str, Any]] = []
        self.error: Exception | None = None
        self.command_error: Exception | None = None
        self.fetch_count = 0
        self.record_fetch_count = 0
        self.connect_count = 0
        self.closed = False
        self._listener: tuple[RecordCallback, ConnectionCallback, ConnectionCallback] | None = None
        self._listening: asyncio.Event | None = None

    def __repr__(self) -> str:
        return f"FakeBackend({list(self.records)!r})"

    @property
    def listening(self) -> bool:
        """Whether a ``listen`` call is active."""
        return self._listener is not None

    async def connect(self) -> None:
        self.connect_count += 1
        if self.error is not None:
            raise self.error

    async def account_email(self) -> str:
        return self.email

    async def fetch_records(self) -> list[dict]:
        self.fetch_count += 1
        if self.error is not None:
            raise self.error
        return [copy.deepcopy(record) for record in self.records.values()]

    async def fetch_record(self, appliance_id: str) -> dict:
        self.record_fetch_count += 1
        if self.error is not None:
            raise self.error
        if appliance_id not in self.records:
            raise FrigidaireException(f"Appliance {appliance_id} is not on the account")
        return copy.deepcopy(self.records[appliance_id])

    async def send(self, appliance_id: str, key: str, value: Any) -> None:
        if self.command_error is not None:
            raise self.command_error
        self.commands.append((key, value))
        self.sent.append((appliance_id, key, value))

    async def listen(
        self,
        on_record: RecordCallback,
        on_connect: ConnectionCallback,
        on_disconnect: ConnectionCallback,
    ) -> None:
        if not self.supports_live_updates:
            raise NotImplementedError("This FakeBackend has supports_live_updates set to False")
        self._listener = (on_record, on_connect, on_disconnect)
        self._event().set()
        on_connect()
        try:
            await asyncio.Event().wait()  # until cancelled
        finally:
            self._listener = None
            self._event().clear()
            on_disconnect()

    async def close(self) -> None:
        self.closed = True

    # --- helpers for tests ---

    async def push(self, record: dict, *, timeout: float = 5.0) -> None:
        """Deliver ``record`` to the active ``listen`` callback, as a live update would.

        The record also replaces the stored one, so later fetches agree with the stream. Waits up
        to ``timeout`` seconds for ``listen`` to start, then yields once so the callback's effects
        can run.
        """
        on_record = (await self._active(timeout))[0]
        record = copy.deepcopy(record)
        self.records[record["applianceId"]] = copy.deepcopy(record)
        on_record(record)
        await asyncio.sleep(0)

    async def reconnect(self, *, timeout: float = 5.0) -> None:
        """Simulate the live stream dropping and coming back: ``on_disconnect`` then ``on_connect``."""
        _, on_connect, on_disconnect = await self._active(timeout)
        on_disconnect()
        on_connect()
        await asyncio.sleep(0)

    def _event(self) -> asyncio.Event:
        if self._listening is None:
            self._listening = asyncio.Event()
        return self._listening

    async def _active(self, timeout: float) -> tuple[RecordCallback, ConnectionCallback, ConnectionCallback]:
        if self._listener is None:
            try:
                await asyncio.wait_for(self._event().wait(), timeout)
            except asyncio.TimeoutError:
                raise RuntimeError("No listen() call is active on this FakeBackend") from None
        assert self._listener is not None
        return self._listener


def FakeAsyncFrigidaire(
    records: list[dict] | None = None,
    *,
    email: str = "user@example.com",
    supports_live_updates: bool = False,
) -> AsyncFrigidaire:
    """An :class:`~frigidaire.client.AsyncFrigidaire` on a new :class:`FakeBackend`.

    The fake is ``client.backend``; annotate it as ``FakeBackend`` to reach its helpers.
    """
    return AsyncFrigidaire(FakeBackend(records, email=email, supports_live_updates=supports_live_updates))


# Names served from a backend package on first use, so importing this module imports no backend.
_FROM_BACKENDS = {"FakeFrigidaire": "frigidaire.backends.password.testing"}


def __getattr__(name: str) -> Any:
    if name in _FROM_BACKENDS:
        value = getattr(importlib.import_module(_FROM_BACKENDS[name]), name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
