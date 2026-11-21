"""The command planners encode the protocol quirks so callers do not have to.

Every command sequence is tested once, here, with no client: a plan is what both clients send,
one request per component, in order. ``test_client.py`` and ``tests/password/test_sync_client.py``
check that each client sends exactly these plans.
"""

from __future__ import annotations

import pytest

from frigidaire import Action, Appliance, Component, FanSpeed, FrigidaireException, Mode, Power, Unit
from frigidaire.model import (
    plan_set_clean_air_mode,
    plan_set_display_light,
    plan_set_fan_speed,
    plan_set_humidity,
    plan_set_mode,
    plan_set_power,
    plan_set_sleep_mode,
    plan_set_start_time,
    plan_set_stop_time,
    plan_set_temperature,
    plan_set_ui_lock,
    plan_set_vertical_swing,
)
from tests.conftest import make_raw_appliance
from tests.plans import steps as _steps


def _flat(plan: list[list[Component]]) -> list[dict]:
    """The requests a plan puts on the wire, in order: one body per component."""
    return [{component.name: component.value} for action in plan for component in action]


def _ac(**reported) -> Appliance:
    base = {"applianceState": "RUNNING", "mode": "COOL", "temperatureRepresentation": "FAHRENHEIT"}
    return Appliance(make_raw_appliance("AC", appliance_id="AC1", reported={**base, **reported}))


def _dh(**reported) -> Appliance:
    base = {"applianceState": "RUNNING", "mode": "DRY"}
    return Appliance(make_raw_appliance("DH", appliance_id="AC1", reported={**base, **reported}))


def test_ac_set_mode_on_running_unit_sends_power_then_mode() -> None:
    assert _flat(plan_set_mode(_ac(), Mode.FAN)) == [{"executeCommand": "ON"}, {"mode": "FANONLY"}]


@pytest.mark.parametrize("mode_name", ["HEAT", "COOL", "ECO"])
def test_ac_set_mode_on_running_unit_preserves_requested_mode(mode_name: str) -> None:
    plan = plan_set_mode(_ac(targetTemperatureF=72), Mode[mode_name])

    assert _flat(plan) == [{"executeCommand": "ON"}, {"mode": mode_name}]


@pytest.mark.parametrize("off_report", [{"applianceState": "off"}, {"mode": "off"}])
@pytest.mark.parametrize(
    "unit,target_key,target", [("fahrenheit", "targetTemperatureF", 72), ("celsius", "targetTemperatureC", 22)]
)
def test_ac_set_heat_from_off_restores_setpoint_last(off_report: dict, unit: str, target_key: str, target: int) -> None:
    """Synthetic off snapshots exercise both off signals and each reported temperature unit."""
    appliance = _ac(**{**off_report, "temperatureRepresentation": unit, target_key: target})

    assert _flat(plan_set_mode(appliance, Mode.HEAT)) == [
        {"executeCommand": "ON"},
        {"mode": "HEAT"},
        {"temperatureRepresentation": unit.upper()},
        {target_key: target},
    ]


def test_ac_set_heat_from_off_without_setpoint_skips_it() -> None:
    assert _flat(plan_set_mode(_ac(applianceState="OFF"), Mode.HEAT)) == [{"executeCommand": "ON"}, {"mode": "HEAT"}]


def test_ac_set_mode_from_off_resends_setpoint_last() -> None:
    """The appliance forgets its setpoint on power-on and the mode restores a default."""
    plan = plan_set_mode(_ac(applianceState="OFF", targetTemperatureF=72), Mode.COOL)

    assert _flat(plan) == [
        {"executeCommand": "ON"},
        {"mode": "COOL"},
        {"temperatureRepresentation": "FAHRENHEIT"},
        {"targetTemperatureF": 72},
    ]


def test_ac_set_mode_from_off_without_setpoint_skips_it() -> None:
    assert _flat(plan_set_mode(_ac(mode="OFF"), Mode.COOL)) == [{"executeCommand": "ON"}, {"mode": "COOL"}]


def test_ac_auto_is_sent_as_eco() -> None:
    """An AC silently ignores Mode.AUTO; its energy-saving mode is ECO."""
    assert _flat(plan_set_mode(_ac(), Mode.AUTO))[-1] == {"mode": "ECO"}


def test_ac_set_mode_off_sends_only_mode_off() -> None:
    assert _flat(plan_set_mode(_ac(), Mode.OFF)) == [{"mode": "OFF"}]


def test_dh_set_mode_powers_on_first_only_when_off() -> None:
    assert _flat(plan_set_mode(_dh(applianceState="OFF"), Mode.CONTINUOUS)) == [
        {"executeCommand": "ON"},
        {"mode": "CONTINUOUS"},
    ]
    assert _flat(plan_set_mode(_dh(), Mode.CONTINUOUS)) == [{"mode": "CONTINUOUS"}]


def test_set_humidity_rounds_to_five_and_enters_dry_mode_first() -> None:
    assert _flat(plan_set_humidity(_dh(mode="AUTO"), 52)) == [{"mode": "DRY"}, {"targetHumidity": 50}]


def test_set_humidity_out_of_range_raises_while_planning() -> None:
    """Planning raises, so a client sends nothing for an invalid target."""
    with pytest.raises(FrigidaireException, match="between 35 and 85"):
        plan_set_humidity(_dh(), 90)


def test_set_temperature_defaults_to_the_appliance_unit() -> None:
    plan = plan_set_temperature(_ac(temperatureRepresentation="celsius"), 22)

    assert _flat(plan) == [{"temperatureRepresentation": "CELSIUS"}, {"targetTemperatureC": 22}]


def test_set_temperature_explicit_unit() -> None:
    plan = plan_set_temperature(_ac(), 72, Unit.FAHRENHEIT)

    assert _flat(plan) == [{"temperatureRepresentation": "FAHRENHEIT"}, {"targetTemperatureF": 72}]


def test_set_temperature_without_a_reported_unit_is_fahrenheit() -> None:
    appliance = Appliance(make_raw_appliance("AC", appliance_id="AC1", reported={}))

    assert _flat(plan_set_temperature(appliance, 72.6)) == [  # type: ignore[arg-type]
        {"temperatureRepresentation": "FAHRENHEIT"},
        {"targetTemperatureF": 72},
    ]


def test_simple_setters() -> None:
    appliance = _ac()
    plans = [
        plan_set_power(appliance, False),
        plan_set_fan_speed(appliance, FanSpeed.MEDIUM),
        plan_set_sleep_mode(appliance, True),
        plan_set_vertical_swing(appliance, False),
        plan_set_ui_lock(appliance, True),
        plan_set_display_light(appliance, True),
        plan_set_clean_air_mode(appliance, False),
        plan_set_start_time(appliance, 1800),
        plan_set_stop_time(appliance, 0),
    ]

    assert [_flat(plan) for plan in plans] == [
        [{"executeCommand": "OFF"}],
        [{"fanSpeedSetting": "MIDDLE"}],
        [{"sleepMode": "ON"}],
        [{"verticalSwing": "OFF"}],
        [{"uiLockMode": True}],
        [{"displayLight": "DISPLAY_LIGHT_1"}],
        [{"cleanAirMode": "OFF"}],
        [{"startTime": 1800}],
        [{"stopTime": 0}],
    ]


def test_negative_timer_raises_while_planning() -> None:
    with pytest.raises(FrigidaireException):
        plan_set_start_time(_ac(), -1)
    with pytest.raises(FrigidaireException):
        plan_set_stop_time(_ac(), -1)


def test_plan_steps_are_the_action_builders() -> None:
    """Each step is one Action builder's component list, so a client can send them as 1.0 did."""
    plan = plan_set_mode(_ac(applianceState="OFF", targetTemperatureF=72), Mode.COOL)

    assert _steps(plan) == [
        _steps([Action.set_power(Power.ON)])[0],
        _steps([Action.set_mode(Mode.COOL)])[0],
        _steps([Action.set_temperature(72, Unit.FAHRENHEIT)])[0],
    ]
    assert len(plan[2]) == 2


def test_planning_does_not_touch_the_snapshot() -> None:
    appliance = _ac(applianceState="OFF", targetTemperatureF=72)
    before = dict(appliance.reported)

    plan_set_mode(appliance, Mode.AUTO)
    plan_set_humidity(_dh(), 50)

    assert appliance.reported == before
