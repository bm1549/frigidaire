"""Builds internal records from the official API's list, info and state responses.

This module works on the plain dicts the SDK's models dump to, so it never imports the SDK.
The record follows :mod:`frigidaire.backends.base`::

    {
        "applianceId": "...",                      # from the list item
        "applianceData": {
            "modelName": "AC",                     # the list item's applianceType
            "applianceName": "Bedroom AC",         # the list item's applianceName
            "created": "2024-01-01T00:00:00Z",     # the list item's creation time, ISO 8601
            "applianceInfo": {...},                # the info call's applianceInfo, when known
            "capabilities": {...},                 # the info call's capabilities, when known
        },
        "properties": {"reported": {...}},         # the state call's reported properties
        "connectionState": "Connected",            # from the state call
        "status": "enabled",                       # from the state call
    }
"""

from __future__ import annotations

import copy
from typing import Any


def build_record(appliance: dict[str, Any], info: dict[str, Any] | None, state: dict[str, Any]) -> dict:
    """One appliance's internal record, as a fresh copy.

    :param appliance: The appliance's item from the list call (``applianceId``, ``applianceName``,
        ``applianceType``, ``created``).
    :param info: The appliance's info call (``applianceInfo``, ``capabilities``), or ``None`` when
        it is not known yet.
    :param state: The appliance's state call (``connectionState``, ``status``, ``properties``).
    """
    appliance_data: dict[str, Any] = {
        "modelName": appliance.get("applianceType"),
        "applianceName": appliance.get("applianceName"),
        "created": appliance.get("created"),
    }
    if info is not None:
        appliance_data["applianceInfo"] = copy.deepcopy(info.get("applianceInfo"))
        appliance_data["capabilities"] = copy.deepcopy(info.get("capabilities"))

    properties = state.get("properties")
    reported = properties.get("reported") if isinstance(properties, dict) else None

    return {
        "applianceId": appliance.get("applianceId"),
        "applianceData": appliance_data,
        "properties": {"reported": copy.deepcopy(reported) if isinstance(reported, dict) else {}},
        "connectionState": state.get("connectionState"),
        "status": state.get("status"),
    }
