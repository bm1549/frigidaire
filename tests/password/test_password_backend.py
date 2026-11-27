"""The password backend: login, records from the one list call, and errors, on a worker thread.

The transport underneath is tested synchronously in the other test_* modules; command sequences
are tested once, as plans, in tests/test_planners.py.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest
import responses

from frigidaire import (
    AuthenticationError,
    Backend,
    FrigidaireException,
    JsonFileSessionStore,
    Mode,
    PasswordBackend,
    SessionCapError,
)
from frigidaire.testing import DEHUMIDIFIER, LEGACY_AC
from tests.password.helpers import APPLIANCES_URL, IDENTITY_DOMAIN, NO_RATE_LIMIT, REGIONAL_URL, USERS_CURRENT_URL
from tests.password.test_authenticate import _stub_full_auth

pytestmark = pytest.mark.usefixtures("http_mock")

PASSWORD = "test-password-do-not-leak"


def _backend(**overrides: object) -> PasswordBackend:
    kwargs: dict[str, object] = {"session_key": "valid-key", "regional_base_url": REGIONAL_URL, **NO_RATE_LIMIT}
    kwargs.update(overrides)
    return PasswordBackend("user@example.com", PASSWORD, **kwargs)  # type: ignore[arg-type]


def _calls(url: str) -> list[responses.Call]:
    return [c for c in responses.calls if c.request.url == url]


def test_implements_the_protocol_without_live_updates() -> None:
    backend = _backend()
    assert isinstance(backend, Backend)
    assert backend.supports_live_updates is False


def test_repr_hides_the_password() -> None:
    assert PASSWORD not in repr(_backend())


async def test_connect_runs_the_full_login_and_reports_the_username() -> None:
    _stub_full_auth()
    backend = PasswordBackend("user@example.com", PASSWORD, **NO_RATE_LIMIT)  # type: ignore[arg-type]

    await backend.connect()

    assert backend.transport is not None
    assert backend.transport.session_key == "FINAL-ACCESS-TOKEN"
    assert await backend.account_email() == "user@example.com"


async def test_connect_reuses_a_stored_session(tmp_path: Path) -> None:
    store = JsonFileSessionStore(str(tmp_path / "s.json"))
    store.save("STORED-KEY", REGIONAL_URL)
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)

    backend = PasswordBackend("u@example.com", PASSWORD, session_store=store, **NO_RATE_LIMIT)  # type: ignore[arg-type]
    await backend.connect()

    assert backend.transport is not None
    assert backend.transport.session_key == "STORED-KEY"
    assert [c.request.url for c in responses.calls] == [USERS_CURRENT_URL]


async def test_connecting_again_validates_the_session_instead_of_logging_in() -> None:
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)
    backend = _backend()
    await backend.connect()
    transport = backend.transport

    await backend.connect()

    assert backend.transport is transport
    assert len(_calls(USERS_CURRENT_URL)) == 2


async def test_rejected_password_raises_authentication_error_without_the_password() -> None:
    _stub_full_auth()
    responses.replace(
        responses.POST,
        f"https://accounts.{IDENTITY_DOMAIN}/accounts.login",
        json={"errorCode": 403042, "errorMessage": "Invalid LoginID"},
        status=200,
    )
    backend = PasswordBackend("user@example.com", PASSWORD, **NO_RATE_LIMIT)  # type: ignore[arg-type]
    with pytest.raises(AuthenticationError) as exc_info:
        await backend.connect()
    assert PASSWORD not in str(exc_info.value)


async def test_methods_connect_first_when_needed() -> None:
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)
    responses.add(responses.GET, APPLIANCES_URL, json=[LEGACY_AC], status=200)

    records = await _backend().fetch_records()

    assert [r["applianceId"] for r in records] == ["AC-LEGACY-1"]
    assert [c.request.url for c in responses.calls] == [USERS_CURRENT_URL, APPLIANCES_URL]


async def test_blocking_calls_run_on_a_worker_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)
    backend = _backend()
    await backend.connect()
    assert backend.transport is not None
    threads: list[threading.Thread] = []

    def fake_list() -> list[dict]:
        threads.append(threading.current_thread())
        return []

    monkeypatch.setattr(backend.transport, "get_appliances_raw", fake_list)
    await backend.fetch_records()

    assert threads and threads[0] is not threading.current_thread()


async def test_fetch_record_filters_the_one_list_call() -> None:
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)
    responses.add(responses.GET, APPLIANCES_URL, json=[LEGACY_AC, DEHUMIDIFIER], status=200)
    backend = _backend()

    record = await backend.fetch_record("DH-1")

    assert record == DEHUMIDIFIER
    assert len(_calls(APPLIANCES_URL)) == 1


async def test_fetch_record_of_an_appliance_not_on_the_account_raises() -> None:
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)
    responses.add(responses.GET, APPLIANCES_URL, json=[LEGACY_AC], status=200)
    with pytest.raises(FrigidaireException, match="not on the account"):
        await _backend().fetch_record("DH-1")


async def test_send_puts_one_property() -> None:
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)
    command_url = f"{REGIONAL_URL}/appliance/api/v2/appliances/AC-LEGACY-1/command"
    responses.add(responses.PUT, command_url, json={}, status=200)

    await _backend().send("AC-LEGACY-1", "mode", Mode.COOL)

    assert [json.loads(c.request.body) for c in _calls(command_url)] == [{"mode": "COOL"}]


async def test_session_cap_propagates_without_logging_in_again() -> None:
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)
    responses.add(responses.GET, APPLIANCES_URL, json={"error": "cas_3403"}, status=429)
    _stub_full_auth()

    with pytest.raises(SessionCapError):
        await _backend().fetch_records()
    assert all("accounts.login" not in c.request.url for c in responses.calls)


async def test_listen_is_not_supported() -> None:
    with pytest.raises(NotImplementedError):
        await _backend().listen(lambda record: None, lambda: None, lambda: None)


async def test_close_releases_the_http_session(monkeypatch: pytest.MonkeyPatch) -> None:
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)
    backend = _backend()
    await backend.close()  # before connect: nothing to close
    await backend.connect()
    assert backend.transport is not None
    closed: list[bool] = []
    monkeypatch.setattr(backend.transport._session, "close", lambda: closed.append(True))

    await backend.close()

    assert closed == [True]
