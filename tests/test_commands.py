"""Appliance commands encode the protocol quirks so callers do not have to.

Every command sequence is tested once, here, against the fake backend: the facade sends one
property per ``backend.send`` call, so the recorded ``(key, value)`` pairs are exactly what each
backend sends, one request each.
"""

from __future__ import annotations

import pytest

from frigidaire import Appliance, FanSpeed, Frigidaire, FrigidaireException, Mode, Unit
from frigidaire.testing import FakeBackend
from tests.conftest import make_raw_appliance


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def client(backend: FakeBackend) -> Frigidaire:
    return Frigidaire(backend)


def _sent(backend: FakeBackend) -> list[dict]:
    return [{key: value} for key, value in backend.commands]


def _ac(**reported) -> Appliance:
    base = {"applianceState": "RUNNING", "mode": "COOL", "temperatureRepresentation": "FAHRENHEIT"}
    return Appliance(make_raw_appliance("AC", appliance_id="AC1", reported={**base, **reported}))


def _dh(**reported) -> Appliance:
    base = {"applianceState": "RUNNING", "mode": "DRY"}
    return Appliance(make_raw_appliance("DH", appliance_id="AC1", reported={**base, **reported}))


async def test_ac_set_mode_on_running_unit_sends_power_then_mode(client: Frigidaire, backend: FakeBackend) -> None:
    await client.set_mode(_ac(), Mode.FAN)

    assert _sent(backend) == [{"executeCommand": "ON"}, {"mode": "FANONLY"}]


@pytest.mark.parametrize("mode_name", ["HEAT", "COOL", "ECO"])
async def test_ac_set_mode_on_running_unit_preserves_requested_mode(
    mode_name: str, client: Frigidaire, backend: FakeBackend
) -> None:
    await client.set_mode(_ac(targetTemperatureF=72), Mode[mode_name])

    assert _sent(backend) == [{"executeCommand": "ON"}, {"mode": mode_name}]


@pytest.mark.parametrize("off_report", [{"applianceState": "off"}, {"mode": "off"}])
@pytest.mark.parametrize(
    "unit,target_key,target", [("fahrenheit", "targetTemperatureF", 72), ("celsius", "targetTemperatureC", 22)]
)
async def test_ac_set_heat_from_off_restores_setpoint_last(
    off_report: dict, unit: str, target_key: str, target: int, client: Frigidaire, backend: FakeBackend
) -> None:
    """Synthetic off snapshots exercise both off signals and each reported temperature unit."""
    appliance = _ac(**{**off_report, "temperatureRepresentation": unit, target_key: target})

    await client.set_mode(appliance, Mode.HEAT)

    assert _sent(backend) == [
        {"executeCommand": "ON"},
        {"mode": "HEAT"},
        {"temperatureRepresentation": unit.upper()},
        {target_key: target},
    ]


async def test_ac_set_heat_from_off_without_setpoint_skips_it(client: Frigidaire, backend: FakeBackend) -> None:
    await client.set_mode(_ac(applianceState="OFF"), Mode.HEAT)

    assert _sent(backend) == [{"executeCommand": "ON"}, {"mode": "HEAT"}]


async def test_ac_set_mode_from_off_resends_setpoint_last(client: Frigidaire, backend: FakeBackend) -> None:
    """The appliance forgets its setpoint on power-on and the mode restores a default."""

    await client.set_mode(_ac(applianceState="OFF", targetTemperatureF=72), Mode.COOL)

    assert _sent(backend) == [
        {"executeCommand": "ON"},
        {"mode": "COOL"},
        {"temperatureRepresentation": "FAHRENHEIT"},
        {"targetTemperatureF": 72},
    ]


async def test_ac_set_mode_from_off_without_setpoint_skips_it(client: Frigidaire, backend: FakeBackend) -> None:
    await client.set_mode(_ac(mode="OFF"), Mode.COOL)

    assert _sent(backend) == [{"executeCommand": "ON"}, {"mode": "COOL"}]


async def test_ac_auto_is_sent_as_eco(client: Frigidaire, backend: FakeBackend) -> None:
    """An AC silently ignores Mode.AUTO; its energy-saving mode is ECO."""

    await client.set_mode(_ac(), Mode.AUTO)

    assert _sent(backend)[-1] == {"mode": "ECO"}


async def test_ac_set_mode_off_sends_only_mode_off(client: Frigidaire, backend: FakeBackend) -> None:
    await client.set_mode(_ac(), Mode.OFF)

    assert _sent(backend) == [{"mode": "OFF"}]


async def test_dh_set_mode_powers_on_first_only_when_off(client: Frigidaire, backend: FakeBackend) -> None:
    await client.set_mode(_dh(applianceState="OFF"), Mode.CONTINUOUS)
    assert _sent(backend) == [{"executeCommand": "ON"}, {"mode": "CONTINUOUS"}]

    backend.commands.clear()
    await client.set_mode(_dh(), Mode.CONTINUOUS)
    assert _sent(backend) == [{"mode": "CONTINUOUS"}]


async def test_set_humidity_rounds_to_five_and_enters_dry_mode_first(client: Frigidaire, backend: FakeBackend) -> None:
    await client.set_humidity(_dh(mode="AUTO"), 52)

    assert _sent(backend) == [{"mode": "DRY"}, {"targetHumidity": 50}]


async def test_set_humidity_out_of_range_raises_before_sending_anything(
    client: Frigidaire, backend: FakeBackend
) -> None:
    with pytest.raises(FrigidaireException, match="between 35 and 85"):
        await client.set_humidity(_dh(), 90)
    assert _sent(backend) == []


async def test_set_temperature_defaults_to_the_appliance_unit(client: Frigidaire, backend: FakeBackend) -> None:
    await client.set_temperature(_ac(temperatureRepresentation="celsius"), 22)

    assert _sent(backend) == [{"temperatureRepresentation": "CELSIUS"}, {"targetTemperatureC": 22}]


async def test_set_temperature_explicit_unit(client: Frigidaire, backend: FakeBackend) -> None:
    await client.set_temperature(_ac(), 72, Unit.FAHRENHEIT)

    assert _sent(backend) == [{"temperatureRepresentation": "FAHRENHEIT"}, {"targetTemperatureF": 72}]


async def test_simple_setters(client: Frigidaire, backend: FakeBackend) -> None:
    appliance = _ac()

    await client.set_power(appliance, False)
    await client.set_fan_speed(appliance, FanSpeed.MEDIUM)
    await client.set_sleep_mode(appliance, True)
    await client.set_vertical_swing(appliance, False)
    await client.set_ui_lock(appliance, True)
    await client.set_display_light(appliance, True)
    await client.set_clean_air_mode(appliance, False)
    await client.set_start_time(appliance, 1800)
    await client.set_stop_time(appliance, 0)

    assert _sent(backend) == [
        {"executeCommand": "OFF"},
        {"fanSpeedSetting": "MIDDLE"},
        {"sleepMode": "ON"},
        {"verticalSwing": "OFF"},
        {"uiLockMode": True},
        {"displayLight": "DISPLAY_LIGHT_1"},
        {"cleanAirMode": "OFF"},
        {"startTime": 1800},
        {"stopTime": 0},
    ]
