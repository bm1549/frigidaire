"""Every backend honours the Backend protocol the same way.

Each case builds a backend serving the same two appliances (``tests.contract.RECORDS``), plus a
way to read back what it sent. The fake needs no mocking and is defined here. Each real backend's
case lives in its own test package, as ``tests/<backend>/contract_case.py``, and is found by name,
so this file imports no backend and deleting a backend's tests removes its case.
"""

from __future__ import annotations

import asyncio
import importlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from frigidaire import Appliance, Backend, FrigidaireException, Mode
from frigidaire.testing import DEHUMIDIFIER, FakeBackend
from tests.contract import IDS, RECORDS, Case, CaseFactory


def _fake(live: bool) -> Case:
    backend = FakeBackend(RECORDS, supports_live_updates=live)
    return Case(backend, lambda: list(backend.sent))


def _backend_cases() -> dict[str, CaseFactory]:
    """Every ``CASES`` from the ``contract_case`` modules of the backend test packages."""
    cases: dict[str, CaseFactory] = {}
    for path in sorted(Path(__file__).parent.glob("*/contract_case.py")):
        module = importlib.import_module(f"{__package__}.{path.parent.name}.contract_case")
        cases.update(module.CASES)
    return cases


FACTORIES: dict[str, CaseFactory] = {
    "fake": lambda: _fake(live=False),
    "fake-live": lambda: _fake(live=True),
    **_backend_cases(),
}


@pytest.fixture(params=list(FACTORIES))
def case(request: pytest.FixtureRequest) -> Iterator[Case]:
    built = FACTORIES[request.param]()
    try:
        yield built
    finally:
        built.cleanup()


async def test_implements_the_protocol(case: Case) -> None:
    assert isinstance(case.backend, Backend)
    assert isinstance(case.backend.supports_live_updates, bool)


async def test_connect_then_account_email(case: Case) -> None:
    await case.backend.connect()
    email = await case.backend.account_email()
    assert isinstance(email, str) and "@" in email


async def test_fetch_records_returns_internal_records(case: Case) -> None:
    await case.backend.connect()
    records = await case.backend.fetch_records()

    assert [r["applianceId"] for r in records] == IDS
    for record in records:
        assert isinstance(record["applianceData"]["modelName"], str)
        assert isinstance(record["applianceData"]["applianceName"], str)
        assert isinstance(record["properties"]["reported"], dict)
        assert Appliance(record).destination is not None
    assert [r["properties"]["reported"] for r in records] == [r["properties"]["reported"] for r in RECORDS]


async def test_fetch_records_returns_fresh_copies(case: Case) -> None:
    await case.backend.connect()
    (await case.backend.fetch_records())[0]["properties"]["reported"]["mode"] = "MUTATED"
    assert (await case.backend.fetch_records())[0]["properties"]["reported"]["mode"] != "MUTATED"


async def test_fetch_record_returns_that_appliance(case: Case) -> None:
    await case.backend.connect()
    record = await case.backend.fetch_record("DH-1")
    assert record["applianceId"] == "DH-1"
    assert record["properties"]["reported"] == DEHUMIDIFIER["properties"]["reported"]


async def test_fetch_record_of_unknown_appliance_raises(case: Case) -> None:
    await case.backend.connect()
    with pytest.raises(FrigidaireException):
        await case.backend.fetch_record("NOT-ON-ACCOUNT")


async def test_send_delivers_one_property_per_call(case: Case) -> None:
    await case.backend.connect()
    await case.backend.send("AC-LEGACY-1", "executeCommand", "ON")
    await case.backend.send("AC-LEGACY-1", "mode", Mode.COOL)
    await case.backend.send("DH-1", "targetHumidity", 50)

    assert case.sent() == [
        ("AC-LEGACY-1", "executeCommand", "ON"),
        ("AC-LEGACY-1", "mode", "COOL"),
        ("DH-1", "targetHumidity", 50),
    ]


async def test_listen_streams_or_refuses(case: Case) -> None:
    await case.backend.connect()
    if not case.backend.supports_live_updates:
        with pytest.raises(NotImplementedError):
            await case.backend.listen(lambda record: None, lambda: None, lambda: None)
        return

    connected = asyncio.Event()
    task = asyncio.create_task(case.backend.listen(lambda record: None, connected.set, lambda: None))
    await asyncio.wait_for(connected.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_close(case: Case) -> None:
    await case.backend.connect()
    await case.backend.close()
