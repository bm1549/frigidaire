"""Shared fixtures and helpers for the test suite.

Nothing here knows about a backend. Each backend's own helpers and fixtures live in its test
package (``tests/password``, ``tests/api_key``), so deleting a backend deletes them too.
"""

from __future__ import annotations

import pytest

from frigidaire import Appliance
from frigidaire.model import _WARNED_APPLIANCE_IDS


@pytest.fixture(autouse=True)
def _reset_warned_appliances() -> None:
    _WARNED_APPLIANCE_IDS.clear()


def make_raw_appliance(
    model_name: str = "AC",
    reported: dict | None = None,
    nickname: str = "Living Room",
    appliance_id: str = "FAKE-ID-123",
) -> dict:
    """Build the raw applianceData shape returned by /appliance/api/v2/appliances."""
    return {
        "applianceId": appliance_id,
        "applianceData": {"modelName": model_name, "applianceName": nickname},
        "properties": {"reported": reported or {}},
    }


def make_appliance(model_name: str = "AC", appliance_id: str = "AC1", nickname: str = "x") -> Appliance:
    """Build a constructed Appliance (no reported properties)."""
    return Appliance(make_raw_appliance(model_name=model_name, appliance_id=appliance_id, nickname=nickname))
