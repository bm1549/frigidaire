"""Appliance commands encode the protocol quirks so callers do not have to."""

import json

import pytest
import responses

from frigidaire import Appliance, FanSpeed, FrigidaireException, Mode, Unit
from tests.conftest import REGIONAL_URL, make_authenticated_client, make_raw_appliance

COMMAND_URL = f"{REGIONAL_URL}/appliance/api/v2/appliances/AC1/command"


def _puts() -> list[dict]:
    return [json.loads(c.request.body) for c in responses.calls if c.request.method == "PUT"]


def _ac(**reported) -> Appliance:
    base = {"applianceState": "RUNNING", "mode": "COOL", "temperatureRepresentation": "FAHRENHEIT"}
    return Appliance(make_raw_appliance("AC", appliance_id="AC1", reported={**base, **reported}))


def _dh(**reported) -> Appliance:
    base = {"applianceState": "RUNNING", "mode": "DRY"}
    return Appliance(make_raw_appliance("DH", appliance_id="AC1", reported={**base, **reported}))


@responses.activate
def test_ac_set_mode_on_running_unit_sends_power_then_mode() -> None:
    client = make_authenticated_client()
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)

    client.set_mode(_ac(), Mode.FAN)

    assert _puts() == [{"executeCommand": "ON"}, {"mode": "FANONLY"}]


@responses.activate
def test_ac_set_mode_from_off_resends_setpoint_last() -> None:
    """The appliance forgets its setpoint on power-on and the mode restores a default."""
    client = make_authenticated_client()
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)

    client.set_mode(_ac(applianceState="OFF", targetTemperatureF=72), Mode.COOL)

    assert _puts() == [
        {"executeCommand": "ON"},
        {"mode": "COOL"},
        {"temperatureRepresentation": "FAHRENHEIT"},
        {"targetTemperatureF": 72},
    ]


@responses.activate
def test_ac_set_mode_from_off_without_setpoint_skips_it() -> None:
    client = make_authenticated_client()
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)

    client.set_mode(_ac(mode="OFF"), Mode.COOL)

    assert _puts() == [{"executeCommand": "ON"}, {"mode": "COOL"}]


@responses.activate
def test_ac_auto_is_sent_as_eco() -> None:
    """An AC silently ignores Mode.AUTO; its energy-saving mode is ECO."""
    client = make_authenticated_client()
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)

    client.set_mode(_ac(), Mode.AUTO)

    assert _puts()[-1] == {"mode": "ECO"}


@responses.activate
def test_ac_set_mode_off_sends_only_mode_off() -> None:
    client = make_authenticated_client()
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)

    client.set_mode(_ac(), Mode.OFF)

    assert _puts() == [{"mode": "OFF"}]


@responses.activate
def test_dh_set_mode_powers_on_first_only_when_off() -> None:
    client = make_authenticated_client()
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)

    client.set_mode(_dh(applianceState="OFF"), Mode.CONTINUOUS)
    assert _puts() == [{"executeCommand": "ON"}, {"mode": "CONTINUOUS"}]

    responses.calls.reset()
    client.set_mode(_dh(), Mode.CONTINUOUS)
    assert _puts() == [{"mode": "CONTINUOUS"}]


@responses.activate
def test_set_humidity_rounds_to_five_and_enters_dry_mode_first() -> None:
    client = make_authenticated_client()
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)

    client.set_humidity(_dh(mode="AUTO"), 52)

    assert _puts() == [{"mode": "DRY"}, {"targetHumidity": 50}]


@responses.activate
def test_set_humidity_out_of_range_raises_before_sending_anything() -> None:
    client = make_authenticated_client()
    with pytest.raises(FrigidaireException, match="between 35 and 85"):
        client.set_humidity(_dh(), 90)
    assert _puts() == []


@responses.activate
def test_set_temperature_defaults_to_the_appliance_unit() -> None:
    client = make_authenticated_client()
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)

    client.set_temperature(_ac(temperatureRepresentation="celsius"), 22)

    assert _puts() == [{"temperatureRepresentation": "CELSIUS"}, {"targetTemperatureC": 22}]


@responses.activate
def test_set_temperature_explicit_unit() -> None:
    client = make_authenticated_client()
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)

    client.set_temperature(_ac(), 72, Unit.FAHRENHEIT)

    assert _puts() == [{"temperatureRepresentation": "FAHRENHEIT"}, {"targetTemperatureF": 72}]


@responses.activate
def test_simple_setters() -> None:
    client = make_authenticated_client()
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)
    appliance = _ac()

    client.set_power(appliance, False)
    client.set_fan_speed(appliance, FanSpeed.MEDIUM)
    client.set_sleep_mode(appliance, True)
    client.set_vertical_swing(appliance, False)
    client.set_ui_lock(appliance, True)
    client.set_display_light(appliance, True)
    client.set_clean_air_mode(appliance, False)
    client.set_start_time(appliance, 1800)
    client.set_stop_time(appliance, 0)

    assert _puts() == [
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
