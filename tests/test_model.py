"""Tests for the parsed appliance model: case-insensitive enums and Appliance accessors."""

import pytest

from frigidaire import (
    Alert,
    Appliance,
    ApplianceState,
    ConnectionState,
    Destination,
    FanSpeed,
    FilterState,
    Mode,
    Unit,
)
from tests.conftest import make_raw_appliance as _raw

# --- case-insensitive enums ---


@pytest.mark.parametrize(
    "cls,value,expected",
    [
        (ApplianceState, "running", ApplianceState.RUNNING),
        (ApplianceState, "RUNNING", ApplianceState.RUNNING),
        (Mode, "fanOnly", Mode.FAN),
        (Mode, "FANONLY", Mode.FAN),
        (FanSpeed, "middle", FanSpeed.MEDIUM),
        (Unit, "fahrenheit", Unit.FAHRENHEIT),
        (FilterState, "good", FilterState.GOOD),
        (ConnectionState, "Connected", ConnectionState.CONNECTED),
        (Alert, "bucket_full", Alert.BUCKET_FULL),
    ],
)
def test_enums_parse_any_casing(cls, value, expected) -> None:
    assert cls(value) is expected


def test_unknown_enum_value_still_raises() -> None:
    with pytest.raises(ValueError):
        Mode("warp")


# --- identity and connection ---


def test_appliance_identity_fields() -> None:
    appliance = Appliance(_raw("AC", nickname="Bedroom", appliance_id="AC1"))
    assert appliance.appliance_id == "AC1"
    assert appliance.nickname == "Bedroom"
    assert appliance.appliance_type == "AC"
    assert appliance.destination is Destination.AIR_CONDITIONER


def test_connection_state_parsed_from_record_sibling_of_properties() -> None:
    record = {**_raw("AC"), "connectionState": "Connected"}
    appliance = Appliance(record)
    assert appliance.connection_state is ConnectionState.CONNECTED
    assert appliance.is_connected is True


def test_disconnected_appliance() -> None:
    appliance = Appliance({**_raw("AC"), "connectionState": "Disconnected"})
    assert appliance.is_connected is False


def test_missing_connection_state_is_none() -> None:
    appliance = Appliance(_raw("AC"))
    assert appliance.connection_state is None
    assert appliance.is_connected is None


def test_reported_is_the_raw_dict_and_get_reads_it() -> None:
    appliance = Appliance(_raw("AC", reported={"mode": "cool", "customKey": 7}))
    assert appliance.reported == {"mode": "cool", "customKey": 7}
    assert appliance.get("customKey") == 7
    assert appliance.get("absent") is None


def test_missing_properties_gives_empty_reported() -> None:
    appliance = Appliance({"applianceId": "X", "applianceData": {"modelName": "AC", "applianceName": "n"}})
    assert appliance.reported == {}
    assert appliance.state is None


# --- operating state ---


def test_state_and_modes_parse_lowercase_firmware_spellings() -> None:
    appliance = Appliance(_raw("AC", reported={"applianceState": "running", "mode": "eco", "modeState": "fanOnly"}))
    assert appliance.state is ApplianceState.RUNNING
    assert appliance.mode is Mode.ECO
    assert appliance.mode_state is Mode.FAN


def test_unknown_mode_is_none_but_raw_still_available() -> None:
    appliance = Appliance(_raw("AC", reported={"mode": "warp"}))
    assert appliance.mode is None
    assert appliance.get("mode") == "warp"


def test_fan_speeds() -> None:
    appliance = Appliance(_raw("AC", reported={"fanSpeedSetting": "auto", "fanSpeedState": "high"}))
    assert appliance.fan_speed is FanSpeed.AUTO
    assert appliance.fan_speed_state is FanSpeed.HIGH


# --- temperatures ---


def test_temperatures_follow_reported_unit() -> None:
    appliance = Appliance(
        _raw(
            "AC",
            reported={
                "temperatureRepresentation": "fahrenheit",
                "ambientTemperatureF": 75,
                "targetTemperatureF": 72,
                "ambientTemperatureC": 24,
                "targetTemperatureC": 22,
            },
        )
    )
    assert appliance.temperature_unit is Unit.FAHRENHEIT
    assert appliance.ambient_temperature == 75
    assert appliance.target_temperature == 72


def test_temperatures_in_celsius() -> None:
    appliance = Appliance(
        _raw(
            "AC",
            reported={"temperatureRepresentation": "CELSIUS", "ambientTemperatureC": 24, "targetTemperatureC": 22},
        )
    )
    assert appliance.temperature_unit is Unit.CELSIUS
    assert appliance.ambient_temperature == 24
    assert appliance.target_temperature == 22


def test_temperature_unit_inferred_from_whichever_reading_is_present() -> None:
    """Some dehumidifiers report a room temperature but no temperatureRepresentation."""
    appliance = Appliance(_raw("DH", reported={"ambientTemperatureC": 21}))
    assert appliance.temperature_unit is Unit.CELSIUS
    assert appliance.ambient_temperature == 21


def test_no_temperature_reported() -> None:
    appliance = Appliance(_raw("DH", reported={}))
    assert appliance.temperature_unit is None
    assert appliance.ambient_temperature is None
    assert appliance.target_temperature is None


# --- humidity ---


def test_humidity_readings() -> None:
    appliance = Appliance(_raw("DH", reported={"sensorHumidity": 55, "targetHumidity": 45}))
    assert appliance.humidity == 55
    assert appliance.target_humidity == 45


def test_readings_keep_the_reported_number_type() -> None:
    """An integer reading must not gain a spurious decimal; a string reading is parsed."""
    assert isinstance(Appliance(_raw("DH", reported={"sensorHumidity": 55})).humidity, int)
    assert Appliance(_raw("DH", reported={"sensorHumidity": "55.5"})).humidity == 55.5


@pytest.mark.parametrize("value", [-1, 101, "n/a", None])
def test_implausible_humidity_is_none(value) -> None:
    appliance = Appliance(_raw("DH", reported={"sensorHumidity": value}))
    assert appliance.humidity is None


# --- filter ---


def test_filter_state_and_attention() -> None:
    assert Appliance(_raw("AC", reported={"filterState": "good"})).filter_state is FilterState.GOOD
    assert Appliance(_raw("AC", reported={"filterState": "good"})).filter_needs_attention is False
    assert Appliance(_raw("AC", reported={"filterState": "CLEAN"})).filter_needs_attention is True
    assert Appliance(_raw("AC", reported={})).filter_needs_attention is None


def test_unknown_filter_state_still_needs_attention() -> None:
    appliance = Appliance(_raw("AC", reported={"filterState": "REPLACE_SOON"}))
    assert appliance.filter_state is None
    assert appliance.filter_needs_attention is True


def test_filter_runtime_seconds() -> None:
    assert Appliance(_raw("AC", reported={"airFilterLifeTime": 3600})).filter_runtime_seconds == 3600
    # Husky/Eagle dehumidifiers report it under a different key (frigidaire#43 payload).
    assert Appliance(_raw("Husky", reported={"filterRuntime": 36000})).filter_runtime_seconds == 36000
    assert Appliance(_raw("AC", reported={"airFilterLifeTime": -5})).filter_runtime_seconds is None
    assert Appliance(_raw("AC", reported={"airFilterLifeTime": "x"})).filter_runtime_seconds is None
    assert Appliance(_raw("AC", reported={})).filter_runtime_seconds is None


# --- alerts and bucket ---


def test_alerts_from_list_of_codes() -> None:
    appliance = Appliance(_raw("DH", reported={"alerts": ["bucket_full"]}))
    assert appliance.alerts == ["BUCKET_FULL"]


def test_alerts_from_list_of_objects() -> None:
    appliance = Appliance(_raw("DH", reported={"alerts": [{"code": "BUCKET_FULL", "severity": 1}]}))
    assert appliance.alerts == ["BUCKET_FULL"]


def test_alerts_absent_is_none_and_empty_is_empty() -> None:
    assert Appliance(_raw("DH", reported={})).alerts is None
    assert Appliance(_raw("DH", reported={"alerts": []})).alerts == []


@pytest.mark.parametrize(
    "reported,expected",
    [
        ({"alerts": ["BUCKET_FULL"]}, True),
        ({"waterBucketLevel": 1}, True),
        ({"waterTankFull": "yes"}, True),
        ({"waterTankFull": True}, True),
        ({"alerts": [], "waterBucketLevel": 0, "waterTankFull": "NO"}, False),
        ({}, None),
    ],
)
def test_bucket_full_from_any_reported_signal(reported, expected) -> None:
    assert Appliance(_raw("DH", reported=reported)).bucket_full is expected


# --- on/off settings ---


@pytest.mark.parametrize("value,expected", [(True, True), (False, False), ("true", True), ("FALSE", False)])
def test_ui_locked_accepts_bool_or_string(value, expected) -> None:
    assert Appliance(_raw("AC", reported={"uiLockMode": value})).ui_locked is expected


def test_ui_locked_absent_is_none() -> None:
    assert Appliance(_raw("AC", reported={})).ui_locked is None


def test_display_light_uses_api_specific_values() -> None:
    assert Appliance(_raw("DH", reported={"displayLight": "DISPLAY_LIGHT_1"})).display_light is True
    assert Appliance(_raw("DH", reported={"displayLight": "display_light_0"})).display_light is False
    assert Appliance(_raw("DH", reported={})).display_light is None


def test_clean_air_sleep_and_swing() -> None:
    appliance = Appliance(_raw("AC", reported={"cleanAirMode": "on", "sleepMode": "OFF", "verticalSwing": "on"}))
    assert appliance.clean_air_mode is True
    assert appliance.sleep_mode is False
    assert appliance.vertical_swing is True


def test_swing_absent_means_unsupported() -> None:
    assert Appliance(_raw("AC", reported={})).vertical_swing is None


# --- timers, air quality, network ---


def test_timers() -> None:
    appliance = Appliance(_raw("AC", reported={"startTime": 1800, "stopTime": 0}))
    assert appliance.start_time == 1800
    assert appliance.stop_time == 0
    assert Appliance(_raw("AC", reported={})).start_time is None


def test_pm25() -> None:
    assert Appliance(_raw("AC", reported={"pm25": 2})).pm25 == 2
    assert Appliance(_raw("AC", reported={"pm25": -1})).pm25 is None
    assert Appliance(_raw("AC", reported={})).pm25 is None


def test_network_interface() -> None:
    appliance = Appliance(_raw("AC", reported={"networkInterface": {"linkQualityIndicator": "excellent", "rssi": -41}}))
    assert appliance.wifi_rssi == -41
    assert appliance.wifi_link_quality == "EXCELLENT"


def test_network_placeholder_rssi_rejected() -> None:
    appliance = Appliance(_raw("AC", reported={"networkInterface": {"rssi": 0}}))
    assert appliance.wifi_rssi is None
    assert appliance.wifi_link_quality is None


def test_network_absent() -> None:
    appliance = Appliance(_raw("AC", reported={}))
    assert appliance.wifi_rssi is None
    assert appliance.wifi_link_quality is None
