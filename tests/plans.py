"""Every client command with sample arguments and the planner it must send, for the client tests.

Both clients' tests check that each command sends exactly ``planner(appliance, *args)``, so no
command sequence is written twice. The sequences themselves are tested in ``test_planners.py``.
"""

from __future__ import annotations

from collections.abc import Callable

import frigidaire.model as m
from frigidaire import Appliance, Component, FanSpeed, Mode, Unit
from tests.conftest import make_raw_appliance

Planner = Callable[..., list[list[Component]]]

OFF_AC = Appliance(
    make_raw_appliance(
        "AC",
        appliance_id="AC1",
        reported={
            "applianceState": "OFF",
            "mode": "OFF",
            "temperatureRepresentation": "FAHRENHEIT",
            "targetTemperatureF": 70,
        },
    )
)
OFF_DH = Appliance(make_raw_appliance("DH", appliance_id="AC1", reported={"applianceState": "OFF", "mode": "DRY"}))

COMMANDS: list[tuple[str, Appliance, tuple, Planner]] = [
    ("set_power", OFF_AC, (True,), m.plan_set_power),
    ("set_mode", OFF_AC, (Mode.COOL,), m.plan_set_mode),
    ("set_mode", OFF_AC, (Mode.AUTO,), m.plan_set_mode),
    ("set_mode", OFF_DH, (Mode.CONTINUOUS,), m.plan_set_mode),
    ("set_temperature", OFF_AC, (22, Unit.CELSIUS), m.plan_set_temperature),
    ("set_fan_speed", OFF_AC, (FanSpeed.HIGH,), m.plan_set_fan_speed),
    ("set_humidity", OFF_DH, (52,), m.plan_set_humidity),
    ("set_sleep_mode", OFF_AC, (True,), m.plan_set_sleep_mode),
    ("set_vertical_swing", OFF_AC, (True,), m.plan_set_vertical_swing),
    ("set_ui_lock", OFF_AC, (False,), m.plan_set_ui_lock),
    ("set_display_light", OFF_DH, (False,), m.plan_set_display_light),
    ("set_clean_air_mode", OFF_DH, (True,), m.plan_set_clean_air_mode),
    ("set_start_time", OFF_AC, (1800,), m.plan_set_start_time),
    ("set_stop_time", OFF_AC, (3600,), m.plan_set_stop_time),
]

COMMAND_IDS = [f"{name}-{appliance.destination.value}-{args[0]}" for name, appliance, args, _ in COMMANDS]


def steps(plan: list[list[Component]]) -> list[list[tuple[str, object]]]:
    """A plan as (name, value) pairs, one list per action."""
    return [[(component.name, component.value) for component in action] for action in plan]
