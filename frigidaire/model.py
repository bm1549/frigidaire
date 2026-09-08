"""The appliance model: the wire vocabulary as enums, and a parsed per-appliance snapshot."""

from __future__ import annotations

import logging
import math
from collections.abc import Mapping
from enum import Enum
from typing import Any

from .exceptions import FrigidaireException

_LOGGER = logging.getLogger(__name__)


class CaseInsensitiveEnum(str, Enum):
    """Older firmware reports ``RUNNING``; newer firmware reports ``running``. Both parse."""

    @classmethod
    def _missing_(cls, value: object) -> Any:
        if isinstance(value, str):
            upper = value.upper()
            for member in cls:
                if member.value == upper:
                    return member
        return None


class Destination(str, Enum):
    AIR_CONDITIONER = "AC"
    DEHUMIDIFIER = "DH"

    @classmethod
    def from_appliance_type(cls, appliance_type: str) -> Destination:
        """
        Maps known model names to their corresponding destination types.
        Falls back to direct enum lookup for backward compatibility.

        :param appliance_type: The model name from the appliance data
        :return: The appropriate Destination enum value
        :raises ValueError: If the model name is not recognized
        """
        if appliance_type in _MODEL_MAPPINGS:
            return _MODEL_MAPPINGS[appliance_type]
        try:
            return cls(appliance_type)
        except ValueError as e:
            raise ValueError(
                f"'{appliance_type}' is not a recognized model name or destination type. "
                f"Known destinations: {list(cls)}, "
                f"Known models: {list(_MODEL_MAPPINGS.keys())}"
            ) from e


# Electrolux internal platform codenames, which newer devices report in
# applianceData.modelName instead of the legacy "AC"/"DH" values.
_MODEL_MAPPINGS: dict[str, Destination] = {
    "Husky": Destination.DEHUMIDIFIER,  # e.g. FHDD5033W1 (50-pint WiFi dehumidifier)
    "Eagle": Destination.DEHUMIDIFIER,  # e.g. GHDD5035W1 (50-pint Gallery WiFi dehumidifier)
    "Panther": Destination.AIR_CONDITIONER,  # e.g. FHWW105WE1 (window inverter AC)
    "Telica": Destination.AIR_CONDITIONER,  # e.g. GHPH142AA1 (portable inverter AC/heat)
}

# Reported property keys unique to each destination, used to infer the destination when
# the codename is unknown. A humidity *reading* (sensorHumidity) is deliberately not a DH
# marker: Telica portable ACs report one too.
_AC_PROPERTY_KEYS = {
    "targetTemperatureC",
    "targetTemperatureF",
    "ambientTemperatureC",
    "ambientTemperatureF",
    "temperatureRepresentation",
}
_DH_PROPERTY_KEYS = {"targetHumidity", "waterBucketLevel", "waterTankFull"}

# Appliances are re-parsed on every poll, so inference warnings are logged once per appliance.
_WARNED_APPLIANCE_IDS: set[str] = set()


def _warn_once(appliance_id: str, message: str, *args: Any) -> None:
    if appliance_id in _WARNED_APPLIANCE_IDS:
        return
    _WARNED_APPLIANCE_IDS.add(appliance_id)
    _LOGGER.warning(message, *args)


class Setting(str, Enum):
    """Writeable settings: names of Components accepted by the command endpoint."""

    # Common
    FAN_SPEED = "fanSpeedSetting"
    EXECUTE_COMMAND = "executeCommand"
    MODE = "mode"
    SLEEP_MODE = "sleepMode"
    UI_LOCK_MODE = "uiLockMode"
    VERTICAL_SWING = "verticalSwing"

    # AC
    TARGET_TEMPERATURE_C = "targetTemperatureC"
    TARGET_TEMPERATURE_F = "targetTemperatureF"
    TEMPERATURE_REPRESENTATION = "temperatureRepresentation"

    # Humidifier
    CLEAN_AIR_MODE = "cleanAirMode"
    DISPLAY_LIGHT = "displayLight"
    START_TIME = "startTime"
    STOP_TIME = "stopTime"
    TARGET_HUMIDITY = "targetHumidity"


class Detail(str, Enum):
    """Readable keys of ``properties.reported``. Not every model reports every key."""

    # Common
    AIR_FILTER_LIFETIME = "airFilterLifeTime"
    FILTER_RUNTIME = "filterRuntime"  # the same reading on Husky/Eagle dehumidifiers
    COMPRESSOR_STATE = "compressorState"  # real telemetry, seen on Husky/Eagle dehumidifiers
    COMPRESSOR_RUNTIME = "compressorRuntime"
    TOTAL_RUNTIME = "totalRuntime"
    ALERTS = "alerts"
    APPLIANCE_STATE = "applianceState"
    APPLIANCE_UI_SW_VERSION = "applianceUiSwVersion"
    FAN_SPEED = "fanSpeedSetting"
    FAN_SPEED_STATE = "fanSpeedState"
    FILTER_STATE = "filterState"
    MODE = "mode"
    # The mode the appliance is *actually* running, which can differ from the requested
    # MODE: an ECO/AUTO unit reports "cool" or "fanOnly" as it cycles.
    MODE_STATE = "modeState"
    NETWORK_INTERFACE = "networkInterface"
    # Room humidity reading. Reported by dehumidifiers and by some ACs (e.g. Telica).
    SENSOR_HUMIDITY = "sensorHumidity"
    UI_LOCK_MODE = "uiLockMode"
    SLEEP_MODE = "sleepMode"
    VERTICAL_SWING = "verticalSwing"

    # AC
    AMBIENT_TEMPERATURE_C = "ambientTemperatureC"
    AMBIENT_TEMPERATURE_F = "ambientTemperatureF"
    TARGET_TEMPERATURE_C = "targetTemperatureC"
    TARGET_TEMPERATURE_F = "targetTemperatureF"
    TEMPERATURE_REPRESENTATION = "temperatureRepresentation"

    # Air quality, on models with a particulate sensor. Units are µg/m³.
    PM1 = "pm1"
    PM10 = "pm10"
    PM25 = "pm25"

    # Humidifier
    CONDENSATE_PUMP = "condensatePump"
    DISPLAY_LIGHT = "displayLight"
    CLEAN_AIR_MODE = "cleanAirMode"
    HEPA_FILTER_INSERTED_STATE = "hepaFilterInsertedState"
    START_TIME = "startTime"
    STOP_TIME = "stopTime"
    TARGET_HUMIDITY = "targetHumidity"
    WATER_BUCKET_LEVEL = "waterBucketLevel"
    WATER_TANK_FULL = "waterTankFull"


class Unit(CaseInsensitiveEnum):
    FAHRENHEIT = "FAHRENHEIT"
    CELSIUS = "CELSIUS"


class ApplianceState(CaseInsensitiveEnum):
    OFF = "OFF"
    RUNNING = "RUNNING"
    DELAYED_START = "DELAYED_START"


class ConnectionState(CaseInsensitiveEnum):
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"


class FilterState(CaseInsensitiveEnum):
    BUY = "BUY"
    CHANGE = "CHANGE"
    CLEAN = "CLEAN"
    GOOD = "GOOD"


class Power(CaseInsensitiveEnum):
    ON = "ON"
    OFF = "OFF"


class SleepMode(CaseInsensitiveEnum):
    ON = "ON"
    OFF = "OFF"


class VerticalSwing(CaseInsensitiveEnum):
    ON = "ON"
    OFF = "OFF"


class DisplayLight(CaseInsensitiveEnum):
    # Unlike most other on/off settings, the API rejects plain "ON"/"OFF" for displayLight.
    ON = "DISPLAY_LIGHT_1"
    OFF = "DISPLAY_LIGHT_0"


class Alert(CaseInsensitiveEnum):
    BUCKET_FULL = "BUCKET_FULL"
    BUS_HIGH_VOLTAGE = "BUS_HIGH_VOLTAGE"
    COMMUNICATION_FAULT = "COMMUNICATION_FAULT"
    DC_MOTOR_FAULT = "DC_MOTOR_FAULT"
    DC_MOTOR_LOST_SPEED = "DC_MOTOR_LOST_SPEED"
    DRAIN_PAN_FULL = "DRAIN_PAN_FULL"
    INDOOR_DEFROST_THERMISTOR_FAULT = "INDOOR_DEFROST_THERMISTOR_FAULT"
    PM25_SENSOR_FAULT = "PM25_SENSOR_FAULT"
    TUBE_HIGH_TEMPERATURE = "TUBE_HIGH_TEMPERATURE"
    UNKNOWN_STATE_ERROR = "UNKNOWN_STATE_ERROR"


class Mode(CaseInsensitiveEnum):
    # Air Conditioner
    OFF = "OFF"
    COOL = "COOL"
    FAN = "FANONLY"
    ECO = "ECO"
    # Dehumidifier
    DRY = "DRY"
    AUTO = "AUTO"
    CONTINUOUS = "CONTINUOUS"
    QUIET = "QUIET"
    SMART = "SMART"


class FanSpeed(CaseInsensitiveEnum):
    # Common
    LOW = "LOW"
    MEDIUM = "MIDDLE"
    HIGH = "HIGH"
    # Air Conditioner
    AUTO = "AUTO"


class Component:
    def __init__(self, name: str | Setting, value: int | str | bool):
        """
        Create a new Component to specify a setting with a name and value.
        Note: String names are discouraged but allowed since not all settings are known at this time.

        :param name: Name of the setting (Setting or a string).
        :param value: Value of the setting
        """
        if isinstance(name, Setting):
            name = name.value
        self.name = name
        self.value = value


class Action:
    """Pure builders for the component lists that execute_action() sends."""

    @classmethod
    def set_power(cls, power: Power) -> list[Component]:
        return [Component(Setting.EXECUTE_COMMAND, power)]

    @classmethod
    def set_mode(cls, mode: Mode) -> list[Component]:
        return [Component(Setting.MODE, mode)]

    @classmethod
    def set_fan_speed(cls, fan_speed: FanSpeed) -> list[Component]:
        return [Component(Setting.FAN_SPEED, fan_speed)]

    @classmethod
    def set_ui_lock_mode(cls, ui_lock_mode: bool) -> list[Component]:
        return [Component(Setting.UI_LOCK_MODE, ui_lock_mode)]

    @classmethod
    def set_vertical_swing(cls, vertical_swing: VerticalSwing) -> list[Component]:
        return [Component(Setting.VERTICAL_SWING, vertical_swing)]

    @classmethod
    def set_sleep_mode(cls, sleep_mode: SleepMode) -> list[Component]:
        return [Component(Setting.SLEEP_MODE, sleep_mode)]

    @classmethod
    def set_display_light(cls, display_light: DisplayLight) -> list[Component]:
        return [Component(Setting.DISPLAY_LIGHT, display_light)]

    @classmethod
    def set_clean_air_mode(cls, on: bool) -> list[Component]:
        return [Component(Setting.CLEAN_AIR_MODE, "ON" if on else "OFF")]

    @classmethod
    def set_stop_time(cls, stop_time: int) -> list[Component]:
        """Stop time in seconds; device snaps to ~30-min increments (min ~1800s, use 0 to clear)."""
        if stop_time < 0:
            raise FrigidaireException("StopTime must be greater than or equal to 0")

        return [Component(Setting.STOP_TIME, stop_time)]

    @classmethod
    def set_start_time(cls, start_time: int) -> list[Component]:
        """Start time in seconds; device snaps to ~30-min increments (min ~1800s, use 0 to clear)."""
        if start_time < 0:
            raise FrigidaireException("StartTime must be greater than or equal to 0")

        return [Component(Setting.START_TIME, start_time)]

    @classmethod
    def set_humidity(cls, humidity: int) -> list[Component]:
        if humidity < 35 or humidity > 85:
            raise FrigidaireException("Humidity must be between 35 and 85 percent, inclusive")

        return [Component(Setting.TARGET_HUMIDITY, humidity)]

    @classmethod
    def set_temperature(cls, temperature: int, temperature_unit: Unit = Unit.FAHRENHEIT) -> list[Component]:
        # Frigidaire enforces inclusive limits of 60-90 °F / 16-32 °C; out-of-range values fail.
        temperature_unit_setting = (
            Setting.TARGET_TEMPERATURE_F if temperature_unit == Unit.FAHRENHEIT else Setting.TARGET_TEMPERATURE_C
        )

        return [
            Component(Setting.TEMPERATURE_REPRESENTATION, temperature_unit),
            Component(temperature_unit_setting, temperature),
        ]


# --- value parsing helpers ---

_TRUE_WORDS = frozenset({"ON", "TRUE", "YES"})
_FALSE_WORDS = frozenset({"OFF", "FALSE", "NO"})


def _parse_enum(cls: type[Any], value: Any) -> Any:
    if value is None:
        return None
    try:
        return cls(value)
    except ValueError:
        return None


def _parse_on_off(value: Any) -> bool | None:
    """Reported on/off settings arrive as bools, ``"true"``/``"false"``, ``"ON"``/``"OFF"`` or ``"YES"``/``"NO"``."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        word = value.upper()
        if word in _TRUE_WORDS:
            return True
        if word in _FALSE_WORDS:
            return False
    return None


def _finite_float(value: Any) -> float | None:
    """A finite number, or None. Integers stay integers so readings keep the precision they were reported with."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _non_negative_float(value: Any) -> float | None:
    number = _finite_float(value)
    return None if number is None or number < 0 else number


def _percent(value: Any) -> float | None:
    number = _finite_float(value)
    return None if number is None or not 0 <= number <= 100 else number


class Appliance:
    """One appliance's identity plus the state it most recently reported.

    Built from one record of the appliance-list response. The typed accessors parse
    ``properties.reported``; ``get()`` reads any key they do not cover. Accessors return
    ``None`` when the model does not report the underlying value, so callers can tell
    "off" from "not supported on this model".
    """

    def __init__(self, record: dict) -> None:
        self.raw: dict = record
        self.appliance_id: str = record["applianceId"]
        data = record.get("applianceData") or {}
        self.appliance_type: str = data["modelName"]
        self.nickname: str = data["applianceName"]
        reported = (record.get("properties") or {}).get("reported")
        self.reported: dict = reported if isinstance(reported, dict) else {}
        # connectionState is a sibling of "properties", so it is not in `reported`.
        raw_connection = record.get("connectionState")
        self.connection_state: ConnectionState | None = _parse_enum(ConnectionState, raw_connection)
        self.is_connected: bool | None = (
            None if raw_connection is None else self.connection_state is ConnectionState.CONNECTED
        )
        self.destination: Destination | None = self._resolve_destination()

    def __repr__(self) -> str:
        return f"Appliance({self.appliance_id!r}, {self.nickname!r}, {self.destination})"

    def _resolve_destination(self) -> Destination | None:
        try:
            return Destination.from_appliance_type(self.appliance_type)
        except ValueError:
            pass

        # Check DH first: its marker keys are exclusive, while the "AC" keys (ambient
        # temperature, temperature representation) are also reported by dehumidifiers
        # that display room temperature.
        reported_keys = set(self.reported)
        for keys, destination in (
            (_DH_PROPERTY_KEYS, Destination.DEHUMIDIFIER),
            (_AC_PROPERTY_KEYS, Destination.AIR_CONDITIONER),
        ):
            if reported_keys & keys:
                _warn_once(
                    self.appliance_id,
                    "Unknown appliance type '%s' for '%s' (%s) — inferred %s from reported properties. "
                    "Please report this at https://github.com/bm1549/frigidaire/issues",
                    self.appliance_type,
                    self.nickname,
                    self.appliance_id,
                    destination.name,
                )
                return destination

        _warn_once(
            self.appliance_id,
            "Unrecognized appliance type '%s' for '%s' (%s) — skipping. Reported keys: %s. "
            "Please report this at https://github.com/bm1549/frigidaire/issues",
            self.appliance_type,
            self.nickname,
            self.appliance_id,
            sorted(reported_keys),
        )
        return None

    # --- raw access ---

    def get(self, key: str) -> Any:
        """Return a reported property by key (a ``Detail`` or a plain string), or None."""
        return self.reported.get(key)

    def _enum(self, cls: type[Any], key: Detail) -> Any:
        return _parse_enum(cls, self.reported.get(key))

    def _on_off(self, key: Detail) -> bool | None:
        return _parse_on_off(self.reported.get(key))

    # --- operating state ---

    @property
    def state(self) -> ApplianceState | None:
        return self._enum(ApplianceState, Detail.APPLIANCE_STATE)

    @property
    def mode(self) -> Mode | None:
        """The requested mode."""
        return self._enum(Mode, Detail.MODE)

    @property
    def mode_state(self) -> Mode | None:
        """The mode the appliance is actually running, on models that report it."""
        return self._enum(Mode, Detail.MODE_STATE)

    @property
    def fan_speed(self) -> FanSpeed | None:
        """The requested fan speed."""
        return self._enum(FanSpeed, Detail.FAN_SPEED)

    @property
    def fan_speed_state(self) -> FanSpeed | None:
        """The fan speed the appliance reports running. May hold its last value while off."""
        return self._enum(FanSpeed, Detail.FAN_SPEED_STATE)

    # --- temperature ---

    @property
    def temperature_unit(self) -> Unit | None:
        """The unit the appliance reports in, inferred from the readings when it omits the representation."""
        unit = self._enum(Unit, Detail.TEMPERATURE_REPRESENTATION)
        if unit is not None:
            return unit
        if self.get(Detail.AMBIENT_TEMPERATURE_F) is not None or self.get(Detail.TARGET_TEMPERATURE_F) is not None:
            return Unit.FAHRENHEIT
        if self.get(Detail.AMBIENT_TEMPERATURE_C) is not None or self.get(Detail.TARGET_TEMPERATURE_C) is not None:
            return Unit.CELSIUS
        return None

    def _temperature(self, fahrenheit: Detail, celsius: Detail) -> float | None:
        unit = self.temperature_unit
        if unit is None:
            return None
        return _finite_float(self.get(fahrenheit if unit is Unit.FAHRENHEIT else celsius))

    @property
    def ambient_temperature(self) -> float | None:
        """Room temperature in ``temperature_unit``."""
        return self._temperature(Detail.AMBIENT_TEMPERATURE_F, Detail.AMBIENT_TEMPERATURE_C)

    @property
    def target_temperature(self) -> float | None:
        """Setpoint in ``temperature_unit``."""
        return self._temperature(Detail.TARGET_TEMPERATURE_F, Detail.TARGET_TEMPERATURE_C)

    # --- humidity ---

    @property
    def humidity(self) -> float | None:
        """Room relative humidity in percent, on models with a humidity sensor."""
        return _percent(self.get(Detail.SENSOR_HUMIDITY))

    @property
    def target_humidity(self) -> float | None:
        return _percent(self.get(Detail.TARGET_HUMIDITY))

    # --- filter ---

    @property
    def filter_state(self) -> FilterState | None:
        return self._enum(FilterState, Detail.FILTER_STATE)

    @property
    def filter_needs_attention(self) -> bool | None:
        """True for any reported filter state other than GOOD, including states this library does not know."""
        raw = self.get(Detail.FILTER_STATE)
        if raw is None:
            return None
        return _parse_enum(FilterState, raw) is not FilterState.GOOD

    @property
    def filter_runtime_seconds(self) -> float | None:
        """Cumulative filter runtime, on models that report it (under either key)."""
        seconds = _non_negative_float(self.get(Detail.AIR_FILTER_LIFETIME))
        return seconds if seconds is not None else _non_negative_float(self.get(Detail.FILTER_RUNTIME))

    # --- alerts and water bucket ---

    @property
    def alerts(self) -> list[str] | None:
        """Active alert codes, upper-cased. The API sends either bare codes or ``{"code": ...}`` objects."""
        value = self.get(Detail.ALERTS)
        if value is None:
            return None
        items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
        codes = []
        for item in items:
            code = item.get("code") if isinstance(item, Mapping) else item
            if code is not None:
                codes.append(str(code).upper())
        return codes

    @property
    def bucket_full(self) -> bool | None:
        """Whether the dehumidifier's bucket is full, from whichever signal this model reports.

        Models differ: a BUCKET_FULL alert, ``waterBucketLevel == 1``, or ``waterTankFull``.
        None when the model reports none of them.
        """
        alerts = self.alerts
        level = self.get(Detail.WATER_BUCKET_LEVEL)
        tank = self.get(Detail.WATER_TANK_FULL)
        if alerts is None and level is None and tank is None:
            return None
        if alerts and Alert.BUCKET_FULL in alerts:
            return True
        if level == 1:
            return True
        return _parse_on_off(tank) is True

    # --- on/off settings ---

    @property
    def sleep_mode(self) -> bool | None:
        return self._on_off(Detail.SLEEP_MODE)

    @property
    def vertical_swing(self) -> bool | None:
        """None on models without a motorised louver, which omit the key entirely."""
        return self._on_off(Detail.VERTICAL_SWING)

    @property
    def ui_locked(self) -> bool | None:
        return self._on_off(Detail.UI_LOCK_MODE)

    @property
    def display_light(self) -> bool | None:
        light = self._enum(DisplayLight, Detail.DISPLAY_LIGHT)
        return None if light is None else light is DisplayLight.ON

    @property
    def clean_air_mode(self) -> bool | None:
        return self._on_off(Detail.CLEAN_AIR_MODE)

    # --- telemetry some models report ---

    @property
    def compressor_running(self) -> bool | None:
        """Real compressor state, on models that report it (Husky/Eagle dehumidifiers do)."""
        return self._on_off(Detail.COMPRESSOR_STATE)

    @property
    def condensate_pump_running(self) -> bool | None:
        return self._on_off(Detail.CONDENSATE_PUMP)

    @property
    def hepa_filter_inserted(self) -> bool | None:
        return self._on_off(Detail.HEPA_FILTER_INSERTED_STATE)

    @property
    def compressor_runtime_seconds(self) -> float | None:
        return _non_negative_float(self.get(Detail.COMPRESSOR_RUNTIME))

    @property
    def total_runtime_seconds(self) -> float | None:
        return _non_negative_float(self.get(Detail.TOTAL_RUNTIME))

    # --- timers ---

    def _timer(self, key: Detail) -> int | None:
        # Some dehumidifiers report -1 (INVALID_OR_NOT_SET_TIME) for a timer that is not set.
        seconds = _finite_float(self.get(key))
        return None if seconds is None else max(0, int(seconds))

    @property
    def start_time(self) -> int | None:
        """Seconds until a scheduled start, or 0 when no start timer is set."""
        return self._timer(Detail.START_TIME)

    @property
    def stop_time(self) -> int | None:
        """Seconds until a scheduled stop, or 0 when no stop timer is set."""
        return self._timer(Detail.STOP_TIME)

    # --- air quality and network ---

    @property
    def pm25(self) -> float | None:
        """PM2.5 concentration in µg/m³, on models with a particulate sensor."""
        return _non_negative_float(self.get(Detail.PM25))

    @property
    def wifi_rssi(self) -> float | None:
        """Wi-Fi signal strength in dBm. A non-negative value is a placeholder and is rejected."""
        network = self.get(Detail.NETWORK_INTERFACE)
        if not isinstance(network, Mapping):
            return None
        rssi = _finite_float(network.get("rssi"))
        return None if rssi is None or rssi >= 0 else rssi

    @property
    def wifi_link_quality(self) -> str | None:
        network = self.get(Detail.NETWORK_INTERFACE)
        if not isinstance(network, Mapping) or network.get("linkQualityIndicator") is None:
            return None
        return str(network["linkQualityIndicator"]).upper()
