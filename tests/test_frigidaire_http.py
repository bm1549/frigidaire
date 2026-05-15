"""Tests for the Frigidaire HTTP orchestration (get_appliances, get_appliance_details, execute_action, re-auth).

The full authenticate() flow is exercised in test_authenticate.py. Here we shortcut
authentication by passing a valid session_key + regional_base_url, which makes
__init__ call test_connection() once and return.
"""

import json

import pytest
import responses

from frigidaire import Action, FrigidaireException, Mode, Power
from tests.conftest import APPLIANCES_URL, REGIONAL_URL, make_appliance, make_authenticated_client


@responses.activate
def test_get_appliances_returns_known_destinations() -> None:
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
    appliances = client.get_appliances()
    assert [a.appliance_id for a in appliances] == ["AC1", "DH1"]


@responses.activate
def test_get_appliances_skips_unresolvable_appliance() -> None:
    client = make_authenticated_client()
    responses.add(
        responses.GET,
        APPLIANCES_URL,
        json=[
            {
                "applianceId": "OK",
                "applianceData": {"modelName": "AC", "applianceName": "n"},
                "properties": {"reported": {}},
            },
            {
                "applianceId": "SKIP",
                "applianceData": {"modelName": "Mystery", "applianceName": "n2"},
                "properties": {"reported": {"unrelated": 1}},
            },
        ],
        status=200,
    )
    appliances = client.get_appliances()
    assert [a.appliance_id for a in appliances] == ["OK"]


@responses.activate
def test_get_appliance_details_finds_matching_appliance() -> None:
    client = make_authenticated_client()
    responses.add(
        responses.GET,
        APPLIANCES_URL,
        json=[
            {
                "applianceId": "AC1",
                "applianceData": {"modelName": "AC", "applianceName": "Bedroom"},
                "properties": {"reported": {"targetTemperatureF": 72, "mode": "COOL"}},
            },
        ],
        status=200,
    )
    details = client.get_appliance_details(make_appliance(nickname="Bedroom"))
    assert details == {"targetTemperatureF": 72, "mode": "COOL"}


@responses.activate
def test_get_appliance_details_raises_when_not_found() -> None:
    client = make_authenticated_client()
    responses.add(responses.GET, APPLIANCES_URL, json=[], status=200)
    with pytest.raises(FrigidaireException, match="not found"):
        client.get_appliance_details(make_appliance(appliance_id="MISSING"))


@responses.activate
def test_execute_action_puts_each_component_separately() -> None:
    """Action.set_temperature returns 2 components; each must be a separate PUT."""
    client = make_authenticated_client()
    command_url = f"{REGIONAL_URL}/appliance/api/v2/appliances/AC1/command"
    responses.add(responses.PUT, command_url, json={}, status=200)

    client.execute_action(make_appliance(), Action.set_temperature(72))

    puts = [c for c in responses.calls if c.request.method == "PUT"]
    assert len(puts) == 2
    bodies = [json.loads(c.request.body) for c in puts]
    assert bodies[0] == {"temperatureRepresentation": "FAHRENHEIT"}
    assert bodies[1] == {"targetTemperatureF": 72}


@responses.activate
def test_execute_action_set_power_sends_one_put() -> None:
    client = make_authenticated_client()
    command_url = f"{REGIONAL_URL}/appliance/api/v2/appliances/AC1/command"
    responses.add(responses.PUT, command_url, json={}, status=200)

    appliance = make_appliance()
    client.execute_action(appliance, Action.set_power(Power.ON))
    client.execute_action(appliance, Action.set_mode(Mode.COOL))

    puts = [c for c in responses.calls if c.request.method == "PUT"]
    assert len(puts) == 2


@responses.activate
def test_request_includes_bearer_token() -> None:
    client = make_authenticated_client()
    responses.add(responses.GET, APPLIANCES_URL, json=[], status=200)
    client.get_appliances()

    call = next(c for c in responses.calls if "appliances?includeMetadata=true" in c.request.url)
    assert call.request.headers["Authorization"] == "Bearer valid-key"
    assert call.request.headers["x-api-key"]  # presence


@responses.activate
def test_429_with_cas_3403_does_not_reauth(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-authenticating on a 429 makes things worse; the library must propagate it."""
    client = make_authenticated_client()
    reauth_called: list[bool] = []
    monkeypatch.setattr(client, "re_authenticate", lambda: reauth_called.append(True))

    responses.add(
        responses.GET,
        APPLIANCES_URL,
        json={"error": "cas_3403", "message": "Too many sessions"},
        status=429,
    )
    with pytest.raises(FrigidaireException):
        client.get_appliances()
    assert reauth_called == []


@responses.activate
def test_get_appliances_reauths_on_non_cas_3403_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A generic failure (not cas_3403) triggers re-authentication and one retry."""
    client = make_authenticated_client()

    reauth_called: list[bool] = []

    def fake_reauth() -> None:
        reauth_called.append(True)
        client.session_key = "new-key"

    monkeypatch.setattr(client, "re_authenticate", fake_reauth)

    # First call fails with a generic 500; second succeeds
    responses.add(responses.GET, APPLIANCES_URL, json={"error": "boom"}, status=500)
    responses.add(responses.GET, APPLIANCES_URL, json=[], status=200)

    appliances = client.get_appliances()
    assert appliances == []
    assert len(reauth_called) == 1


@responses.activate
def test_writes_are_rate_limited_through_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: ensure the limiter is actually wrapping self._session.request.

    The previous autowrap attempted to patch a non-existent self._session and
    silently failed, leaving rate limiting disabled in production.
    """
    sleeps: list[float] = []
    monkeypatch.setattr("frigidaire.rate_limit.time.sleep", lambda s: sleeps.append(s))

    client = make_authenticated_client(rate_limit_min_interval=1.5, rate_limit_jitter=0.0)
    command_url = f"{REGIONAL_URL}/appliance/api/v2/appliances/AC1/command"
    responses.add(responses.PUT, command_url, json={}, status=200)

    appliance = make_appliance()
    client.execute_action(appliance, Action.set_power(Power.ON))
    client.execute_action(appliance, Action.set_power(Power.OFF))

    # First PUT establishes the next-ok-at; second PUT must sleep ~1.5s
    assert any(abs(s - 1.5) < 0.05 for s in sleeps), f"expected a ~1.5s sleep, got {sleeps}"


@responses.activate
def test_execute_action_cas_3403_propagates_without_reauth(monkeypatch: pytest.MonkeyPatch) -> None:
    client = make_authenticated_client()
    reauth_called = []
    monkeypatch.setattr(client, "re_authenticate", lambda: reauth_called.append(True))

    responses.add(
        responses.PUT,
        f"{REGIONAL_URL}/appliance/api/v2/appliances/AC1/command",
        json={"error": "cas_3403"},
        status=429,
    )
    with pytest.raises(FrigidaireException):
        client.execute_action(make_appliance(), Action.set_power(Power.ON))
    assert reauth_called == []  # critical: never re-auth on cas_3403
