"""Tests for the password transport's HTTP orchestration (get_appliances_raw, send_command, re-auth).

The full authenticate() flow is exercised in test_authenticate.py. Here we shortcut
authentication by passing a valid session_key + regional_base_url, which makes
__init__ call test_connection() once and return. Parsing records into appliances is the
facade's job and is tested in test_client.py.
"""

import json

import pytest
import responses

from frigidaire import Action, FrigidaireException, Mode, Power
from frigidaire.backends.password.transport import PasswordTransport
from frigidaire.model import Component
from tests.conftest import make_raw_appliance
from tests.password.helpers import APPLIANCES_URL, REGIONAL_URL, make_authenticated_client


def _send(client: PasswordTransport, action: list[Component], appliance_id: str = "AC1") -> None:
    for component in action:
        client.send_command(appliance_id, component.name, component.value)


@responses.activate
def test_get_appliances_raw_returns_every_record() -> None:
    client = make_authenticated_client()
    responses.add(
        responses.GET,
        APPLIANCES_URL,
        json=[
            {
                "applianceId": "AC1",
                "applianceData": {"modelName": "AC", "applianceName": "Bedroom"},
                "properties": {"reported": {"targetTemperatureF": 72}},
            },
            {
                "applianceId": "DH1",
                "applianceData": {"modelName": "Husky", "applianceName": "Basement"},
                "properties": {"reported": {"targetHumidity": 50}},
            },
        ],
        status=200,
    )
    records = client.get_appliances_raw()
    assert [r["applianceId"] for r in records] == ["AC1", "DH1"]
    assert records[1]["properties"]["reported"] == {"targetHumidity": 50}


@responses.activate
def test_send_command_puts_each_component_separately() -> None:
    """Action.set_temperature returns 2 components; each must be a separate PUT."""
    client = make_authenticated_client()
    command_url = f"{REGIONAL_URL}/appliance/api/v2/appliances/AC1/command"
    responses.add(responses.PUT, command_url, json={}, status=200)

    _send(client, Action.set_temperature(72))

    puts = [c for c in responses.calls if c.request.method == "PUT"]
    assert len(puts) == 2
    bodies = [json.loads(c.request.body) for c in puts]
    assert bodies[0] == {"temperatureRepresentation": "FAHRENHEIT"}
    assert bodies[1] == {"targetTemperatureF": 72}


@responses.activate
def test_send_command_sends_one_put_per_call() -> None:
    client = make_authenticated_client()
    command_url = f"{REGIONAL_URL}/appliance/api/v2/appliances/AC1/command"
    responses.add(responses.PUT, command_url, json={}, status=200)

    _send(client, Action.set_power(Power.ON))
    _send(client, Action.set_mode(Mode.COOL))

    puts = [c for c in responses.calls if c.request.method == "PUT"]
    assert len(puts) == 2


@responses.activate
def test_request_includes_bearer_token() -> None:
    client = make_authenticated_client()
    responses.add(responses.GET, APPLIANCES_URL, json=[], status=200)
    client.get_appliances_raw()

    call = next(c for c in responses.calls if "appliances?includeMetadata=true" in c.request.url)
    assert call.request.headers["Authorization"] == "Bearer valid-key"
    assert call.request.headers["x-api-key"]  # presence


@responses.activate
def test_429_with_cas_3403_does_not_reauth(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-authenticating on a 429 makes things worse; the library must propagate it."""
    client = make_authenticated_client()
    reauth_called: list[bool] = []
    monkeypatch.setattr(client, "_re_authenticate", lambda: reauth_called.append(True))

    responses.add(
        responses.GET,
        APPLIANCES_URL,
        json={"error": "cas_3403", "message": "Too many sessions"},
        status=429,
    )
    with pytest.raises(FrigidaireException):
        client.get_appliances_raw()
    assert reauth_called == []


@responses.activate
def test_transient_failure_retries_on_existing_session_without_reauth(monkeypatch: pytest.MonkeyPatch) -> None:
    """A one-off failure retries on the existing session and must NOT re-authenticate.

    Re-authenticating mints a new server-side session; Electrolux caps active
    sessions (cas_3403), and month-long tokens make abandoned sessions accumulate.
    A transient blip doesn't mean our session is invalid, so we retry first.
    """
    client = make_authenticated_client()
    reauth_called: list[bool] = []
    monkeypatch.setattr(client, "_re_authenticate", lambda: reauth_called.append(True))

    # First call fails with a generic 500; retry on the same session succeeds.
    responses.add(responses.GET, APPLIANCES_URL, json={"error": "boom"}, status=500)
    responses.add(responses.GET, APPLIANCES_URL, json=[], status=200)

    records = client.get_appliances_raw()
    assert records == []
    assert reauth_called == []


@responses.activate
def test_persistent_failure_reauths_after_retry_also_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only when the retry also fails do we conclude the session is bad and re-authenticate."""
    client = make_authenticated_client()

    reauth_called: list[bool] = []

    def fake_reauth() -> None:
        reauth_called.append(True)
        client.session_key = "new-key"

    monkeypatch.setattr(client, "_re_authenticate", fake_reauth)

    # First call and the retry both fail; only then re-auth, and the third call succeeds.
    responses.add(responses.GET, APPLIANCES_URL, json={"error": "boom"}, status=500)
    responses.add(responses.GET, APPLIANCES_URL, json={"error": "boom"}, status=500)
    responses.add(responses.GET, APPLIANCES_URL, json=[], status=200)

    records = client.get_appliances_raw()
    assert records == []
    assert len(reauth_called) == 1


@responses.activate
def test_writes_are_rate_limited_through_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: ensure the limiter is actually wrapping self._session.request.

    The previous autowrap attempted to patch a non-existent self._session and
    silently failed, leaving rate limiting disabled in production.
    """
    sleeps: list[float] = []
    monkeypatch.setattr("frigidaire.backends.password.rate_limit.time.sleep", lambda s: sleeps.append(s))

    client = make_authenticated_client(rate_limit_min_interval=1.5, rate_limit_jitter=0.0)
    command_url = f"{REGIONAL_URL}/appliance/api/v2/appliances/AC1/command"
    responses.add(responses.PUT, command_url, json={}, status=200)

    _send(client, Action.set_power(Power.ON))
    _send(client, Action.set_power(Power.OFF))

    # First PUT establishes the next-ok-at; second PUT must sleep ~1.5s
    assert any(abs(s - 1.5) < 0.05 for s in sleeps), f"expected a ~1.5s sleep, got {sleeps}"


@responses.activate
def test_session_max_retries_zero_makes_single_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    """With session retries disabled, a failure is raised immediately — no retry, no re-auth."""
    client = make_authenticated_client(session_max_retries=0)
    reauth_called: list[bool] = []
    monkeypatch.setattr(client, "_re_authenticate", lambda: reauth_called.append(True))

    responses.add(responses.GET, APPLIANCES_URL, json={"error": "boom"}, status=500)
    with pytest.raises(FrigidaireException):
        client.get_appliances_raw()
    assert reauth_called == []
    appliance_calls = [c for c in responses.calls if c.request.url.startswith(APPLIANCES_URL)]
    assert len(appliance_calls) == 1  # single attempt, no retry


@responses.activate
def test_session_retry_backoff_sleeps_between_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured backoff sleeps before retrying on the existing session."""
    sleeps: list[float] = []
    monkeypatch.setattr("frigidaire.backends.password.transport.time.sleep", lambda s: sleeps.append(s))

    client = make_authenticated_client(session_retry_backoff=0.5)
    monkeypatch.setattr(client, "_re_authenticate", lambda: None)

    responses.add(responses.GET, APPLIANCES_URL, json={"error": "boom"}, status=500)
    responses.add(responses.GET, APPLIANCES_URL, json=[], status=200)

    assert client.get_appliances_raw() == []
    assert any(abs(s - 0.5) < 0.01 for s in sleeps), f"expected a ~0.5s backoff sleep, got {sleeps}"


@responses.activate
def test_send_command_cas_3403_propagates_without_reauth(monkeypatch: pytest.MonkeyPatch) -> None:
    client = make_authenticated_client()
    reauth_called = []
    monkeypatch.setattr(client, "_re_authenticate", lambda: reauth_called.append(True))

    responses.add(
        responses.PUT,
        f"{REGIONAL_URL}/appliance/api/v2/appliances/AC1/command",
        json={"error": "cas_3403"},
        status=429,
    )
    with pytest.raises(FrigidaireException):
        _send(client, Action.set_power(Power.ON))
    assert reauth_called == []  # critical: never re-auth on cas_3403


@responses.activate
def test_get_appliances_raw_returns_fresh_state_each_call() -> None:
    client = make_authenticated_client()
    responses.add(responses.GET, APPLIANCES_URL, json=[make_raw_appliance(reported={"mode": "COOL"})], status=200)
    responses.add(responses.GET, APPLIANCES_URL, json=[make_raw_appliance(reported={"mode": "OFF"})], status=200)
    assert client.get_appliances_raw()[0]["properties"]["reported"]["mode"] == "COOL"
    assert client.get_appliances_raw()[0]["properties"]["reported"]["mode"] == "OFF"


@responses.activate
def test_send_command_retry_after_reauth_carries_the_new_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: the PUT headers were built once, so the retry after re-auth reused the old token."""
    client = make_authenticated_client()
    sent: list[str] = []

    def reauth() -> None:
        client.session_key = "new-key"

    monkeypatch.setattr(client, "_re_authenticate", reauth)

    def put(request: object) -> tuple[int, dict, bytes]:
        authorization = request.headers["Authorization"]  # type: ignore[attr-defined]
        sent.append(authorization)
        return (401, {}, b'{"error":"unauthorized"}') if authorization == "Bearer valid-key" else (200, {}, b"{}")

    responses.add_callback(responses.PUT, f"{REGIONAL_URL}/appliance/api/v2/appliances/AC1/command", callback=put)

    client.send_command("AC1", "executeCommand", "ON")

    assert sent == ["Bearer valid-key", "Bearer valid-key", "Bearer new-key"]


@responses.activate
def test_send_command_uses_a_session_another_thread_just_minted(monkeypatch: pytest.MonkeyPatch) -> None:
    """A retry picks up a session another request re-authenticated meanwhile, without minting one."""
    client = make_authenticated_client()
    reauths: list[bool] = []
    sent: list[str] = []
    monkeypatch.setattr(client, "_re_authenticate", lambda: reauths.append(True))

    def put(request: object) -> tuple[int, dict, bytes]:
        authorization = request.headers["Authorization"]  # type: ignore[attr-defined]
        sent.append(authorization)
        if authorization == "Bearer valid-key":
            client.session_key = "from-other-thread"  # the poll re-authenticated meanwhile
            return (401, {}, b"{}")
        return (200, {}, b"{}")

    responses.add_callback(responses.PUT, f"{REGIONAL_URL}/appliance/api/v2/appliances/AC1/command", callback=put)

    client.send_command("AC1", "executeCommand", "ON")

    assert sent == ["Bearer valid-key", "Bearer from-other-thread"]
    assert reauths == []
