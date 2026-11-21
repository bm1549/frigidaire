"""The synchronous ``Frigidaire`` client of 1.x: the password transport plus parsing and commands.

Transport behaviour (login, retries, throttling, errors) is tested on ``PasswordTransport`` in the
other modules here; the sync client inherits it unchanged. This covers what it adds, and that every
command sends its plan from ``frigidaire.model`` one action per ``execute_action`` call, as 1.0 did.
"""

from __future__ import annotations

import json

import pytest
import responses

import frigidaire
from frigidaire import Action, Appliance, Component, FrigidaireException, Mode, Setting
from frigidaire.backends.password.sync_client import Frigidaire
from frigidaire.backends.password.transport import PasswordTransport
from tests.conftest import make_appliance, make_raw_appliance
from tests.password.helpers import APPLIANCES_URL, REGIONAL_URL, make_sync_client
from tests.plans import COMMAND_IDS, COMMANDS, Planner, steps

COMMAND_URL = f"{REGIONAL_URL}/appliance/api/v2/appliances/AC1/command"


def _puts() -> list[dict]:
    return [json.loads(c.request.body) for c in responses.calls if c.request.method == "PUT"]


def test_is_the_exported_client_and_a_password_transport() -> None:
    assert frigidaire.Frigidaire is Frigidaire
    assert issubclass(Frigidaire, PasswordTransport)


@responses.activate
def test_get_appliances_returns_known_destinations() -> None:
    client = make_sync_client()
    responses.add(
        responses.GET,
        APPLIANCES_URL,
        json=[
            make_raw_appliance("AC", appliance_id="AC1", reported={"targetTemperatureF": 72}),
            make_raw_appliance("Husky", appliance_id="DH1", reported={"targetHumidity": 50}),
        ],
        status=200,
    )
    appliances = client.get_appliances()
    assert [a.appliance_id for a in appliances] == ["AC1", "DH1"]
    assert all(isinstance(a, Appliance) for a in appliances)


@responses.activate
def test_get_appliances_skips_unresolvable_and_malformed_records(caplog: pytest.LogCaptureFixture) -> None:
    client = make_sync_client()
    responses.add(
        responses.GET,
        APPLIANCES_URL,
        json=[
            {"applianceData": {"modelName": "AC", "applianceName": "no id"}},
            make_raw_appliance("Mystery", appliance_id="SKIP", reported={"unrelated": 1}),
            make_raw_appliance("AC", appliance_id="OK"),
        ],
        status=200,
    )
    assert [a.appliance_id for a in client.get_appliances()] == ["OK"]
    assert "malformed" in caplog.text


@responses.activate
def test_get_appliances_returns_fresh_state_each_call() -> None:
    client = make_sync_client()
    responses.add(responses.GET, APPLIANCES_URL, json=[make_raw_appliance(reported={"mode": "COOL"})], status=200)
    responses.add(responses.GET, APPLIANCES_URL, json=[make_raw_appliance(reported={"mode": "OFF"})], status=200)
    assert client.get_appliances()[0].mode is Mode.COOL
    assert client.get_appliances()[0].mode is Mode.OFF


@responses.activate
def test_get_appliances_goes_through_with_reauth(monkeypatch: pytest.MonkeyPatch) -> None:
    client = make_sync_client()
    reauth_called: list[bool] = []
    monkeypatch.setattr(client, "_re_authenticate", lambda: reauth_called.append(True))
    responses.add(responses.GET, APPLIANCES_URL, json={"error": "boom"}, status=500)
    responses.add(responses.GET, APPLIANCES_URL, json=[make_raw_appliance()], status=200)

    assert [a.appliance_id for a in client.get_appliances()] == ["FAKE-ID-123"]
    assert reauth_called == []


@responses.activate
def test_get_appliances_raw_returns_the_records_unparsed() -> None:
    client = make_sync_client()
    responses.add(responses.GET, APPLIANCES_URL, json=[make_raw_appliance("Mystery")], status=200)
    assert [r["applianceData"]["modelName"] for r in client.get_appliances_raw()] == ["Mystery"]


@responses.activate
def test_execute_action_puts_each_component_separately() -> None:
    client = make_sync_client()
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)

    client.execute_action(make_appliance(), Action.set_temperature(72))

    assert _puts() == [{"temperatureRepresentation": "FAHRENHEIT"}, {"targetTemperatureF": 72}]


@responses.activate
def test_command_retry_after_reauthentication_sends_the_new_session_key(monkeypatch: pytest.MonkeyPatch) -> None:
    client = make_sync_client(session_max_retries=1)
    sent_keys: list[str] = []

    def command(request):
        sent_keys.append(request.headers["Authorization"])
        status = 401 if request.headers["Authorization"] == "Bearer valid-key" else 200
        return status, {}, "{}"

    responses.add_callback(responses.PUT, COMMAND_URL, callback=command)

    def fake_reauthenticate() -> None:
        client.session_key = "new-key"

    monkeypatch.setattr(client, "_re_authenticate", fake_reauthenticate)

    client.execute_action(make_appliance(), [Component(Setting.MODE, "COOL")])

    assert sent_keys == ["Bearer valid-key", "Bearer new-key"]


@pytest.mark.parametrize(("name", "appliance", "args", "planner"), COMMANDS, ids=COMMAND_IDS)
@responses.activate
def test_each_command_sends_its_plan_one_action_per_execute_action(
    name: str, appliance: Appliance, args: tuple, planner: Planner, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = make_sync_client()
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)
    actions: list[list[tuple[str, object]]] = []
    execute_action = client.execute_action

    def recording(appliance: Appliance, action: list[Component]) -> None:
        actions.append([(component.name, component.value) for component in action])
        execute_action(appliance, action)

    monkeypatch.setattr(client, "execute_action", recording)

    getattr(client, name)(appliance, *args)

    expected = steps(planner(appliance, *args))
    assert actions == expected
    assert _puts() == [{key: value} for action in expected for key, value in action]


@responses.activate
def test_a_failing_action_stops_the_rest_of_the_plan() -> None:
    client = make_sync_client(session_max_retries=0)
    responses.add(responses.PUT, COMMAND_URL, json={}, status=200)
    responses.add(responses.PUT, COMMAND_URL, json={"error": "boom"}, status=500)
    appliance = Appliance(
        make_raw_appliance("AC", appliance_id="AC1", reported={"applianceState": "OFF", "targetTemperatureF": 72})
    )

    with pytest.raises(FrigidaireException):
        client.set_mode(appliance, Mode.COOL)

    assert _puts() == [{"executeCommand": "ON"}, {"mode": "COOL"}]
