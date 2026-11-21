"""``frigidaire.testing.FakeFrigidaire``: the sync client with no HTTP, exactly as in 1.0.

The 1.0 tests of the fake follow unchanged; the Home Assistant integration's tests depend on it.
"""

from unittest.mock import patch

import pytest

import frigidaire.testing
from frigidaire import Appliance, Frigidaire, FrigidaireException, JsonFileSessionStore, Mode
from frigidaire.backends.password import testing as password_testing
from frigidaire.testing import DEHUMIDIFIER, LEGACY_AC, FakeFrigidaire, with_reported


def test_fake_is_a_frigidaire_client() -> None:
    assert issubclass(FakeFrigidaire, Frigidaire)


def test_fake_is_served_from_the_password_package() -> None:
    assert frigidaire.testing.FakeFrigidaire is password_testing.FakeFrigidaire


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


def test_fake_session_store_is_written_by_persist_session(tmp_path) -> None:
    """The integration swaps the store on the fake and calls _persist_session, as on 1.0."""
    fake = FakeFrigidaire([LEGACY_AC])
    store = JsonFileSessionStore(str(tmp_path / "s.json"))
    fake._session_store = store
    fake._persist_session()
    assert store.load() == ("fake-session-key", "https://api.us.ocp.electrolux.one")


@pytest.mark.parametrize("failure_step", [1, 2, 3])
def test_execute_action_is_called_once_per_action(failure_step: int) -> None:
    """Patching execute_action sees the 1.0 calls: power, mode, then the restored setpoint."""
    fake = FakeFrigidaire([with_reported(LEGACY_AC, applianceState="OFF", targetTemperatureF=70)])
    appliance = fake.get_appliances()[0]
    side_effect = [None] * (failure_step - 1) + [FrigidaireException("command failed")]
    with (
        patch.object(fake, "execute_action", side_effect=side_effect) as execute,
        pytest.raises(FrigidaireException, match="command failed"),
    ):
        fake.set_mode(appliance, Mode.HEAT)
    assert execute.call_count == failure_step
    assert [len(call.args[1]) for call in execute.call_args_list] == [1, 1, 2][:failure_step]


def test_unknown_testing_attribute_raises_attribute_error() -> None:
    with pytest.raises(AttributeError):
        frigidaire.testing.NotAThing  # noqa: B018
