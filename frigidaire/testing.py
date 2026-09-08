"""An in-memory client and sample records for downstream test suites.

``FakeFrigidaire`` replaces only the transport: it serves canned appliance records and
records every command instead of sending it, so the real command builders and parsing
run unchanged.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any, TypeVar

from . import Frigidaire
from .model import Appliance, Component
from .session_store import SessionStore

T = TypeVar("T")

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


class FakeFrigidaire(Frigidaire):
    """A ``Frigidaire`` with no HTTP: canned records in, recorded commands out.

    ``error`` is raised by the next fetch when set. ``commands`` lists every
    ``(setting, value)`` pair sent, in order. ``fetch_count`` counts appliance-list fetch attempts, failed ones included.
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
