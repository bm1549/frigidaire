"""Tests for Action factory methods."""

import json

import pytest

from frigidaire import Action, DisplayLight, FrigidaireException, Setting, Unit


@pytest.mark.parametrize("humidity", [35, 50, 85])
def test_set_humidity_in_range(humidity: int) -> None:
    components = Action.set_humidity(humidity)
    assert components[0].name == Setting.TARGET_HUMIDITY.value
    assert components[0].value == humidity


@pytest.mark.parametrize("humidity", [34, 86, 0, 100, -1])
def test_set_humidity_out_of_range_raises(humidity: int) -> None:
    with pytest.raises(FrigidaireException, match="between 35 and 85"):
        Action.set_humidity(humidity)


def test_set_temperature_fahrenheit_default() -> None:
    components = Action.set_temperature(72)
    # Two components: representation, then the temperature value
    assert len(components) == 2
    assert components[0].name == Setting.TEMPERATURE_REPRESENTATION.value
    assert components[0].value == Unit.FAHRENHEIT
    assert components[1].name == Setting.TARGET_TEMPERATURE_F.value
    assert components[1].value == 72


def test_set_temperature_celsius() -> None:
    components = Action.set_temperature(22, Unit.CELSIUS)
    assert components[0].value == Unit.CELSIUS
    assert components[1].name == Setting.TARGET_TEMPERATURE_C.value
    assert components[1].value == 22


def test_set_display_light_on() -> None:
    components = Action.set_display_light(DisplayLight.ON)
    assert len(components) == 1
    assert components[0].name == Setting.DISPLAY_LIGHT.value
    assert components[0].value == "DISPLAY_LIGHT_1"


def test_set_display_light_off() -> None:
    components = Action.set_display_light(DisplayLight.OFF)
    assert len(components) == 1
    assert components[0].name == Setting.DISPLAY_LIGHT.value
    assert components[0].value == "DISPLAY_LIGHT_0"


def test_display_light_enum_matches_api_values() -> None:
    # The API rejects plain ON/OFF for this setting; a future rename must not
    # silently change the values sent over the wire.
    assert DisplayLight.ON.value == "DISPLAY_LIGHT_1"
    assert DisplayLight.OFF.value == "DISPLAY_LIGHT_0"


def test_set_display_light_serializes_to_api_string() -> None:
    components = Action.set_display_light(DisplayLight.ON)
    assert json.dumps(components[0].value) == '"DISPLAY_LIGHT_1"'
