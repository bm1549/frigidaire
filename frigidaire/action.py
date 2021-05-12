from enum import Enum
from typing import List, Union

from frigidaire.exception import FrigidaireIllegalArgumentException


class Component(dict):
    def __init__(self, name: str, value: Union[int, str]):
        dict.__init__(self, name=name, value=value)


class Power(Enum):
    ON = 1
    OFF = 0


class Mode(Enum):
    COOL = 1
    FAN = 3
    ECO = 4


class FanSpeed(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 4
    AUTO = 7


class Action:
    @classmethod
    def set_power(cls, power: Power) -> List[Component]:
        return [Component("0403", power.value)]

    @classmethod
    def set_mode(cls, mode: Mode) -> List[Component]:
        return [Component("1000", mode.value)]

    @classmethod
    def set_fan_speed(cls, fan_speed: FanSpeed) -> List[Component]:
        return [Component("1002", fan_speed.value)]

    @classmethod
    def set_temperature(cls, temperature: int) -> List[Component]:
        # This is a restriction set by Frigidaire
        if temperature < 60 or temperature > 90:
            raise FrigidaireIllegalArgumentException("Temperature must be between 60 and 90 degrees, inclusive")

        return [
            Component("0432", "Container"),
            Component("1", temperature),  # This is the actual temperature, the rest is some required nonsense
            Component("3", 0),
            Component("0", 1),
        ]
