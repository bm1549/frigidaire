"""The in-memory fake shipped for downstream test suites."""

from __future__ import annotations

import asyncio

import pytest

from frigidaire import Appliance, Backend, Frigidaire, FrigidaireException
from frigidaire.testing import DEHUMIDIFIER, LEGACY_AC, TELICA_AC, FakeBackend, FakeFrigidaire, with_reported


def test_fake_backend_implements_the_protocol() -> None:
    assert isinstance(FakeBackend([]), Backend)


def test_fake_frigidaire_is_a_facade_on_a_fake_backend() -> None:
    client = FakeFrigidaire([LEGACY_AC])
    assert isinstance(client, Frigidaire)
    assert isinstance(client.backend, FakeBackend)
    assert list(client.backend.records) == [LEGACY_AC["applianceId"]]


async def test_fake_serves_snapshots_and_counts_fetches() -> None:
    client = FakeFrigidaire([LEGACY_AC, DEHUMIDIFIER])
    appliances = await client.get_appliances()
    assert [a.appliance_id for a in appliances] == [LEGACY_AC["applianceId"], DEHUMIDIFIER["applianceId"]]
    assert all(isinstance(a, Appliance) for a in appliances)
    backend = client.backend
    assert isinstance(backend, FakeBackend)
    assert backend.fetch_count == 1


async def test_fake_raises_configured_error_until_cleared() -> None:
    backend = FakeBackend([LEGACY_AC])
    backend.error = RuntimeError("boom")
    for call in (backend.connect, backend.fetch_records, lambda: backend.fetch_record("AC-LEGACY-1")):
        with pytest.raises(RuntimeError, match="boom"):
            await call()
    assert backend.fetch_count == 1
    assert backend.record_fetch_count == 1
    backend.error = None
    assert len(await backend.fetch_records()) == 1


async def test_fake_records_commands() -> None:
    client = FakeFrigidaire([LEGACY_AC])
    backend = client.backend
    assert isinstance(backend, FakeBackend)
    await client.set_power((await client.get_appliances())[0], True)
    assert backend.commands == [("executeCommand", "ON")]
    assert backend.sent == [("AC-LEGACY-1", "executeCommand", "ON")]


async def test_fake_records_are_isolated_from_callers() -> None:
    client = FakeFrigidaire([LEGACY_AC])
    (await client.get_appliances())[0].reported["mode"] = "MUTATED"
    assert (await client.get_appliances())[0].get("mode") == LEGACY_AC["properties"]["reported"]["mode"]


async def test_fake_fetch_record_of_unknown_appliance_raises() -> None:
    with pytest.raises(FrigidaireException):
        await FakeBackend([LEGACY_AC]).fetch_record("nope")


async def test_push_updates_the_stored_record_and_waits_for_listen() -> None:
    backend = FakeBackend([LEGACY_AC], supports_live_updates=True)
    received: list[dict] = []
    push = asyncio.create_task(backend.push(with_reported(LEGACY_AC, mode="FANONLY")))
    await asyncio.sleep(0)
    listen = asyncio.create_task(backend.listen(received.append, lambda: None, lambda: None))
    await push
    assert backend.listening
    listen.cancel()
    with pytest.raises(asyncio.CancelledError):
        await listen

    assert [r["properties"]["reported"]["mode"] for r in received] == ["FANONLY"]
    assert (await backend.fetch_record("AC-LEGACY-1"))["properties"]["reported"]["mode"] == "FANONLY"
    assert not backend.listening


async def test_push_without_listen_raises() -> None:
    backend = FakeBackend([LEGACY_AC], supports_live_updates=True)
    with pytest.raises(RuntimeError, match="No listen"):
        await backend.push(LEGACY_AC, timeout=0.01)


def test_sample_records_cover_both_destinations() -> None:
    assert Appliance(TELICA_AC).destination.value == "AC"
    assert Appliance(DEHUMIDIFIER).destination.value == "DH"


def test_with_reported_returns_a_modified_copy() -> None:
    changed = with_reported(LEGACY_AC, mode="OFF")
    assert changed["properties"]["reported"]["mode"] == "OFF"
    assert LEGACY_AC["properties"]["reported"]["mode"] != "OFF"
