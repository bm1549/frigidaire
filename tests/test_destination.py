"""Tests for Destination resolution and Appliance inference."""

import logging

import pytest

from frigidaire import Appliance, Destination
from tests.conftest import make_raw_appliance as _raw

# --- Destination.from_appliance_type ---


@pytest.mark.parametrize(
    "model,expected",
    [
        ("AC", Destination.AIR_CONDITIONER),
        ("DH", Destination.DEHUMIDIFIER),
        ("Husky", Destination.DEHUMIDIFIER),
        ("Eagle", Destination.DEHUMIDIFIER),
        ("Panther", Destination.AIR_CONDITIONER),
        ("Telica", Destination.AIR_CONDITIONER),
    ],
)
def test_from_appliance_type_known(model: str, expected: Destination) -> None:
    assert Destination.from_appliance_type(model) is expected


def test_from_appliance_type_unknown_raises() -> None:
    with pytest.raises(ValueError, match="not a recognized model name"):
        Destination.from_appliance_type("Nonexistent")


# --- Appliance._resolve_destination ---


def test_appliance_known_codename_no_inference_needed() -> None:
    appliance = Appliance(_raw("Husky"))
    assert appliance.destination is Destination.DEHUMIDIFIER


def test_appliance_legacy_ac_string() -> None:
    appliance = Appliance(_raw("AC"))
    assert appliance.destination is Destination.AIR_CONDITIONER


def test_appliance_infers_dh_from_humidity_keys(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)
    appliance = Appliance(_raw("UnknownCodename", reported={"targetHumidity": 50, "sensorHumidity": 48}))
    assert appliance.destination is Destination.DEHUMIDIFIER
    assert "inferred DEHUMIDIFIER" in caplog.text


def test_appliance_infers_dh_from_water_tank_full_key(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)
    appliance = Appliance(_raw("UnknownCodename", reported={"waterTankFull": "YES"}))
    assert appliance.destination is Destination.DEHUMIDIFIER
    assert "inferred DEHUMIDIFIER" in caplog.text


def test_appliance_infers_ac_from_temperature_keys(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)
    appliance = Appliance(_raw("UnknownCodename", reported={"targetTemperatureF": 72, "ambientTemperatureF": 70}))
    assert appliance.destination is Destination.AIR_CONDITIONER
    assert "inferred AIR_CONDITIONER" in caplog.text


def test_appliance_dh_wins_when_both_keys_present(caplog: pytest.LogCaptureFixture) -> None:
    """DH check comes first because dehumidifiers also report ambient temperature."""
    caplog.set_level(logging.WARNING)
    appliance = Appliance(
        _raw(
            "UnknownCodename",
            reported={"targetHumidity": 50, "ambientTemperatureF": 70, "temperatureRepresentation": "F"},
        )
    )
    assert appliance.destination is Destination.DEHUMIDIFIER


def test_appliance_unknown_with_no_inferable_keys_returns_none(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)
    appliance = Appliance(_raw("UnknownCodename", reported={"unrelatedKey": 1}))
    assert appliance.destination is None
    assert "Unrecognized appliance type" in caplog.text


def test_appliance_missing_properties_key_does_not_crash() -> None:
    """The API sometimes omits `properties` entirely; resolver should fall through cleanly."""
    raw = {"applianceId": "X", "applianceData": {"modelName": "Mystery", "applianceName": "n"}}
    appliance = Appliance(raw)
    assert appliance.destination is None
