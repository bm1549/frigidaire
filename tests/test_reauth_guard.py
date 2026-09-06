"""Concurrent failures on one account must re-authenticate once, not once per thread."""

import threading

import pytest
import responses

from frigidaire import FrigidaireException
from tests.conftest import make_authenticated_client


@responses.activate
def test_concurrent_failures_reauthenticate_once(monkeypatch: pytest.MonkeyPatch) -> None:
    client = make_authenticated_client(session_max_retries=1)
    original_key = client.session_key
    both_failed = threading.Barrier(2, timeout=5)
    reauth_calls: list[int] = []

    def fake_reauthenticate() -> None:
        reauth_calls.append(threading.get_ident())
        client.session_key = f"new-key-{len(reauth_calls)}"

    monkeypatch.setattr(client, "re_authenticate", fake_reauthenticate)

    def operation() -> str:
        if client.session_key == original_key:
            both_failed.wait()  # make both threads fail on the original key before either recovers
            raise FrigidaireException("Request failed", status_code=401)
        return client.session_key

    results: list[str] = []
    workers = [threading.Thread(target=lambda: results.append(client._with_reauth(operation))) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)

    assert len(reauth_calls) == 1
    assert results == ["new-key-1", "new-key-1"]


@responses.activate
def test_single_failure_still_reauthenticates(monkeypatch: pytest.MonkeyPatch) -> None:
    client = make_authenticated_client(session_max_retries=1)
    calls: list[str] = []

    def fake_reauthenticate() -> None:
        calls.append("reauth")
        client.session_key = "new-key"

    monkeypatch.setattr(client, "re_authenticate", fake_reauthenticate)
    attempts: list[str | None] = []

    def operation() -> str:
        attempts.append(client.session_key)
        if client.session_key == "valid-key":
            raise FrigidaireException("Request failed", status_code=401)
        return "ok"

    assert client._with_reauth(operation) == "ok"
    assert calls == ["reauth"]
    assert attempts == ["valid-key", "new-key"]
