"""Tests for Mode enum values."""

from frigidaire import Mode


def test_smart_mode_exists() -> None:
    """SMART is a real dehumidifier mode returned by the API; must be a valid Mode."""
    assert Mode("SMART") == Mode.SMART


def test_smart_mode_string_value() -> None:
    assert Mode.SMART == "SMART"
