"""The in-memory fake shipped for downstream test suites."""

from frigidaire import Appliance, Frigidaire, JsonFileSessionStore, Mode
from frigidaire.testing import DEHUMIDIFIER, LEGACY_AC, TELICA_AC, FakeFrigidaire, with_reported


def test_fake_is_a_frigidaire_client() -> None:
    assert issubclass(FakeFrigidaire, Frigidaire)


def test_fake_accepts_the_real_constructor_kwargs(tmp_path) -> None:
    store = JsonFileSessionStore(str(tmp_path / "s.json"))
    fake = FakeFrigidaire([LEGACY_AC], username="u", password="p", timeout=60, session_store=store)
    assert fake.session_key
    assert store.load() == (fake.session_key, fake.regional_base_url)


def test_fake_serves_snapshots_and_counts_fetches() -> None:
    fake = FakeFrigidaire([LEGACY_AC, DEHUMIDIFIER])
    appliances = fake.get_appliances()
    assert [a.appliance_id for a in appliances] == [LEGACY_AC["applianceId"], DEHUMIDIFIER["applianceId"]]
    assert all(isinstance(a, Appliance) for a in appliances)
    assert fake.fetch_count == 1


def test_fake_raises_configured_error() -> None:
    fake = FakeFrigidaire([LEGACY_AC])
    fake.error = RuntimeError("boom")
    try:
        fake.get_appliances()
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected the configured error")
    assert fake.fetch_count == 1


def test_fake_records_commands_through_the_real_builders() -> None:
    fake = FakeFrigidaire([with_reported(LEGACY_AC, applianceState="OFF", targetTemperatureF=70)])
    appliance = fake.get_appliances()[0]

    fake.set_mode(appliance, Mode.COOL)

    assert fake.commands == [
        ("executeCommand", "ON"),
        ("mode", "COOL"),
        ("temperatureRepresentation", "FAHRENHEIT"),
        ("targetTemperatureF", 70),
    ]


def test_fake_records_are_isolated_from_callers() -> None:
    fake = FakeFrigidaire([LEGACY_AC])
    fake.get_appliances()[0].reported["mode"] = "MUTATED"
    assert fake.get_appliances()[0].get("mode") == LEGACY_AC["properties"]["reported"]["mode"]


def test_sample_records_cover_both_destinations() -> None:
    assert Appliance(TELICA_AC).destination.value == "AC"
    assert Appliance(DEHUMIDIFIER).destination.value == "DH"


def test_with_reported_returns_a_modified_copy() -> None:
    changed = with_reported(LEGACY_AC, mode="OFF")
    assert changed["properties"]["reported"]["mode"] == "OFF"
    assert LEGACY_AC["properties"]["reported"]["mode"] != "OFF"
