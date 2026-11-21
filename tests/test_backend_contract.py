"""Every backend honours the Backend protocol the same way.

Each case builds a backend serving the same two appliances, plus a way to read back what it sent.
The password backend runs against ``responses``; the fake needs no mocking.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass

import pytest
import responses

from frigidaire import Appliance, Backend, FrigidaireException, Mode, PasswordBackend
from frigidaire.testing import DEHUMIDIFIER, LEGACY_AC, FakeBackend
from tests.conftest import APPLIANCES_URL, NO_RATE_LIMIT, REGIONAL_URL, USERS_CURRENT_URL

RECORDS = [LEGACY_AC, DEHUMIDIFIER]
IDS = [r["applianceId"] for r in RECORDS]
COMMAND_URL = f"{REGIONAL_URL}/appliance/api/v2/appliances/{{}}/command"


@dataclass
class Case:
    backend: Backend
    sent: Callable[[], list[tuple[str, str, object]]]
    """Every (appliance_id, key, value) the backend has sent, in order."""


def _fake(live: bool) -> Case:
    backend = FakeBackend(RECORDS, supports_live_updates=live)
    return Case(backend, lambda: list(backend.sent))


def _password() -> Case:
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)
    responses.add(responses.GET, APPLIANCES_URL, json=RECORDS, status=200)
    for appliance_id in IDS:
        responses.add(responses.PUT, COMMAND_URL.format(appliance_id), json={}, status=200)
    backend = PasswordBackend(
        "user@example.com",
        "secret",
        session_key="valid-key",
        regional_base_url=REGIONAL_URL,
        **NO_RATE_LIMIT,  # type: ignore[arg-type]
    )

    def sent() -> list[tuple[str, str, object]]:
        result = []
        for call in responses.calls:
            if call.request.method == "PUT":
                appliance_id = call.request.url.split("/appliances/")[1].split("/")[0]
                ((key, value),) = json.loads(call.request.body).items()
                result.append((appliance_id, key, value))
        return result

    return Case(backend, sent)


FACTORIES: dict[str, Callable[[], Case]] = {
    "fake": lambda: _fake(live=False),
    "fake-live": lambda: _fake(live=True),
    "password": _password,
}


@pytest.fixture(params=list(FACTORIES))
def case(request: pytest.FixtureRequest, http_mock: None) -> Case:
    return FACTORIES[request.param]()


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
