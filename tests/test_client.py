"""The async client: parsing records into snapshots, refresh, live updates and one send per component.

Command sequences are tested once, as plans, in test_planners.py; this checks that every command
sends its plan, and covers what the client does around them.
"""

from __future__ import annotations

import asyncio

import pytest

from frigidaire import Action, Appliance, AsyncFrigidaire, FrigidaireException, Mode
from frigidaire.testing import DEHUMIDIFIER, LEGACY_AC, FakeBackend, with_reported
from tests.conftest import make_raw_appliance
from tests.plans import COMMAND_IDS, COMMANDS, Planner, steps


async def test_get_appliances_returns_known_destinations() -> None:
    backend = FakeBackend(
        [
            make_raw_appliance("AC", appliance_id="AC1", reported={"targetTemperatureF": 72}),
            make_raw_appliance("Husky", appliance_id="DH1", reported={"targetHumidity": 50}),
        ]
    )
    appliances = await AsyncFrigidaire(backend).get_appliances()
    assert [a.appliance_id for a in appliances] == ["AC1", "DH1"]
    assert all(isinstance(a, Appliance) for a in appliances)


async def test_get_appliances_skips_unresolvable_appliance() -> None:
    backend = FakeBackend(
        [
            make_raw_appliance("AC", appliance_id="OK"),
            make_raw_appliance("Mystery", appliance_id="SKIP", reported={"unrelated": 1}),
        ]
    )
    assert [a.appliance_id for a in await AsyncFrigidaire(backend).get_appliances()] == ["OK"]


async def test_get_appliances_skips_malformed_record(caplog: pytest.LogCaptureFixture) -> None:
    backend = FakeBackend([make_raw_appliance("AC", appliance_id="OK")])
    backend.records["BAD"] = {"applianceId": "BAD", "applianceData": {"applianceName": "no model"}}
    assert [a.appliance_id for a in await AsyncFrigidaire(backend).get_appliances()] == ["OK"]
    assert "malformed" in caplog.text
    assert "BAD" in caplog.text
    assert "no model" not in caplog.text, "the record body must stay out of the log"


async def test_get_appliances_returns_fresh_state_each_call() -> None:
    backend = FakeBackend([make_raw_appliance(reported={"mode": "COOL"})])
    client = AsyncFrigidaire(backend)
    assert (await client.get_appliances())[0].mode is Mode.COOL
    backend.records["FAKE-ID-123"] = make_raw_appliance(reported={"mode": "OFF"})
    assert (await client.get_appliances())[0].mode is Mode.OFF


async def test_refresh_fetches_only_that_appliance() -> None:
    backend = FakeBackend([LEGACY_AC, DEHUMIDIFIER])
    client = AsyncFrigidaire(backend)
    ac = (await client.get_appliances())[0]
    backend.records[ac.appliance_id] = with_reported(LEGACY_AC, mode="FANONLY")

    refreshed = await client.refresh(ac)

    assert refreshed.appliance_id == ac.appliance_id
    assert refreshed.mode is Mode.FAN
    assert backend.record_fetch_count == 1
    assert backend.fetch_count == 1


async def test_refresh_of_malformed_record_raises() -> None:
    backend = FakeBackend([LEGACY_AC])
    client = AsyncFrigidaire(backend)
    ac = (await client.get_appliances())[0]
    backend.records[ac.appliance_id] = {"applianceId": ac.appliance_id}
    with pytest.raises(FrigidaireException, match="malformed"):
        await client.refresh(ac)


async def test_execute_action_sends_each_component_as_one_send_in_order() -> None:
    backend = FakeBackend([LEGACY_AC])
    client = AsyncFrigidaire(backend)
    ac = (await client.get_appliances())[0]

    await client.execute_action(ac, Action.set_temperature(72))

    assert backend.sent == [
        ("AC-LEGACY-1", "temperatureRepresentation", "FAHRENHEIT"),
        ("AC-LEGACY-1", "targetTemperatureF", 72),
    ]


async def test_command_errors_propagate() -> None:
    backend = FakeBackend([LEGACY_AC])
    client = AsyncFrigidaire(backend)
    ac = (await client.get_appliances())[0]
    backend.command_error = FrigidaireException("rejected")
    with pytest.raises(FrigidaireException, match="rejected"):
        await client.set_power(ac, True)
    assert backend.commands == []


async def test_connect_account_email_and_close_delegate() -> None:
    backend = FakeBackend([LEGACY_AC], email="someone@example.com")
    client = AsyncFrigidaire(backend)
    await client.connect()
    assert await client.account_email() == "someone@example.com"
    await client.close()
    assert backend.connect_count == 1
    assert backend.closed


async def test_listen_delivers_parsed_appliances_and_connection_events() -> None:
    backend = FakeBackend([LEGACY_AC], supports_live_updates=True)
    client = AsyncFrigidaire(backend)
    assert client.supports_live_updates
    updates: list[Appliance] = []
    events: list[str] = []

    task = asyncio.create_task(
        client.listen(updates.append, lambda: events.append("connect"), lambda: events.append("disconnect"))
    )
    await backend.push(with_reported(LEGACY_AC, mode="FANONLY"))
    await backend.reconnect()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert [(a.appliance_id, a.mode) for a in updates] == [("AC-LEGACY-1", Mode.FAN)]
    assert events == ["connect", "disconnect", "connect", "disconnect"]


async def test_listen_skips_malformed_and_unplaceable_records(caplog: pytest.LogCaptureFixture) -> None:
    backend = FakeBackend([LEGACY_AC], supports_live_updates=True)
    updates: list[Appliance] = []
    task = asyncio.create_task(AsyncFrigidaire(backend).listen(updates.append))

    await backend.push({"applianceId": "BAD"})
    await backend.push(make_raw_appliance("Mystery", appliance_id="SKIP", reported={"unrelated": 1}))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert updates == []
    assert "malformed" in caplog.text


async def test_listen_without_live_updates_raises() -> None:
    client = AsyncFrigidaire(FakeBackend([LEGACY_AC]))
    assert not client.supports_live_updates
    with pytest.raises(NotImplementedError):
        await client.listen(lambda appliance: None)


@pytest.mark.parametrize(("name", "appliance", "args", "planner"), COMMANDS, ids=COMMAND_IDS)
async def test_each_command_sends_its_plan_one_action_at_a_time(
    name: str, appliance: Appliance, args: tuple, planner: Planner, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = FakeBackend()
    client = AsyncFrigidaire(backend)
    actions: list[list[tuple[str, object]]] = []
    execute_action = client.execute_action

    async def recording(appliance: Appliance, action: list) -> None:
        actions.append([(component.name, component.value) for component in action])
        await execute_action(appliance, action)

    monkeypatch.setattr(client, "execute_action", recording)

    await getattr(client, name)(appliance, *args)

    expected = steps(planner(appliance, *args))
    assert actions == expected
    assert backend.sent == [(appliance.appliance_id, key, value) for action in expected for key, value in action]


def test_repr_names_the_backend() -> None:
    assert repr(AsyncFrigidaire(FakeBackend([LEGACY_AC]))) == "AsyncFrigidaire(FakeBackend(['AC-LEGACY-1']))"
