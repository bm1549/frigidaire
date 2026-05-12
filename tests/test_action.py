"""Tests for Action factory methods."""

import pytest

from frigidaire import Action, FrigidaireException, Setting, Unit


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
