"""The API key backend against the official SDK, offline.

Every request goes to ``aioresponses`` at the SDK's own URLs (see ``tests.api_key.helpers``).
Command sequences are covered once, against the fake backend; these tests cover login, tokens,
record building, error mapping and the event stream.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from typing import Any

import aiohttp
import pytest

from frigidaire import (
    ApiKeyBackend,
    Appliance,
    AuthenticationError,
    CommandRejectedError,
    FrigidaireException,
    Mode,
    QuotaExceededError,
)
from frigidaire.testing import DEHUMIDIFIER, LEGACY_AC
from tests.api_key.helpers import (
    ACCESS_TOKEN,
    API_KEY,
    APPLIANCES_URL,
    COMMAND_URL,
    CREATED,
    EMAIL_URL,
    INFO_URL,
    LIVESTREAM_URL,
    REFRESH_TOKEN,
    REFRESH_URL,
    STATE_URL,
    STREAM_EVENT,
    STREAM_URL,
    SdkMock,
    _StreamResponse,
    info_payload,
    list_item,
    make_backend,
    make_jwt,
)

# --- records ---


async def test_fetch_records_builds_internal_records(sdk: SdkMock) -> None:
    sdk.serve([LEGACY_AC, DEHUMIDIFIER])

    records = await make_backend().fetch_records()

    assert records[0] == {
        "applianceId": "AC-LEGACY-1",
        "applianceData": {
            "modelName": "AC",
            "applianceName": "Bedroom AC",
            "created": CREATED,
            "applianceInfo": info_payload(LEGACY_AC)["applianceInfo"],
            "capabilities": info_payload(LEGACY_AC)["capabilities"],
        },
        "properties": {"reported": LEGACY_AC["properties"]["reported"]},
        "connectionState": "Connected",
        "status": "enabled",
    }
    assert set(records[1]["applianceData"]["applianceInfo"]) == {
        "serialNumber",
        "pnc",
        "brand",
        "deviceType",
        "model",
        "variant",
        "colour",
    }
    ac, dh = (Appliance(r) for r in records)
    assert (ac.destination, ac.mode, ac.nickname) == ("AC", Mode.COOL, "Bedroom AC")
    assert (dh.destination, dh.mode, dh.humidity) == ("DH", Mode.DRY, 55)


async def test_info_is_fetched_once_per_appliance(sdk: SdkMock) -> None:
    sdk.serve([LEGACY_AC, DEHUMIDIFIER])
    backend = make_backend()

    await backend.fetch_records()
    await backend.fetch_records()
    record = await backend.fetch_record("DH-1")

    assert record["applianceData"]["applianceInfo"]["serialNumber"] == "SN-DH-1"
    for appliance_id in ("AC-LEGACY-1", "DH-1"):
        assert len(sdk.calls("GET", INFO_URL.format(appliance_id))) == 1
    assert len(sdk.calls("GET", STATE_URL.format("AC-LEGACY-1"))) == 2
    assert len(sdk.calls("GET", STATE_URL.format("DH-1"))) == 3
    assert len(sdk.calls("GET", APPLIANCES_URL)) == 2  # fetch_record reuses the cached list


async def test_fetch_record_lists_once_for_an_appliance_it_has_not_seen(sdk: SdkMock) -> None:
    sdk.serve([LEGACY_AC, DEHUMIDIFIER])
    backend = make_backend()

    record = await backend.fetch_record("DH-1")

    assert record["properties"]["reported"] == DEHUMIDIFIER["properties"]["reported"]
    assert len(sdk.calls("GET", APPLIANCES_URL)) == 1
    with pytest.raises(FrigidaireException, match="not on the account"):
        await backend.fetch_record("NOT-ON-ACCOUNT")
    assert len(sdk.calls("GET", STATE_URL.format("NOT-ON-ACCOUNT"))) == 0


async def test_info_failure_still_builds_the_record_and_is_retried(
    sdk: SdkMock, caplog: pytest.LogCaptureFixture
) -> None:
    sdk.add("GET", INFO_URL.format("DH-1"), status=500, payload={"error": "boom"})
    sdk.serve([DEHUMIDIFIER])
    backend = make_backend()

    (first,) = await backend.fetch_records()
    (second,) = await backend.fetch_records()

    assert "applianceInfo" not in first["applianceData"]
    assert first["properties"]["reported"] == DEHUMIDIFIER["properties"]["reported"]
    assert second["applianceData"]["applianceInfo"]["serialNumber"] == "SN-DH-1"
    assert "Could not read the info of appliance DH-1" in caplog.text


async def test_every_state_failing_is_a_failed_fetch_not_an_empty_account(sdk: SdkMock) -> None:
    for record in (LEGACY_AC, DEHUMIDIFIER):
        sdk.add("GET", STATE_URL.format(record["applianceId"]), status=500, payload={"error": "boom"})
    sdk.serve([LEGACY_AC, DEHUMIDIFIER])

    with pytest.raises(FrigidaireException) as err:
        await make_backend().fetch_records()
    assert type(err.value) is FrigidaireException
    assert err.value.status_code == 500


async def test_an_account_without_appliances_is_empty(sdk: SdkMock) -> None:
    sdk.serve([])

    assert await make_backend().fetch_records() == []


async def test_appliance_whose_state_fails_is_skipped_with_a_warning(
    sdk: SdkMock, caplog: pytest.LogCaptureFixture
) -> None:
    sdk.add("GET", STATE_URL.format("DH-1"), status=500, payload={"error": "boom"})
    sdk.serve([LEGACY_AC, DEHUMIDIFIER])

    records = await make_backend().fetch_records()

    assert [r["applianceId"] for r in records] == ["AC-LEGACY-1"]
    assert "Skipping appliance DH-1" in caplog.text


@pytest.mark.parametrize("status", [401, 429])
async def test_auth_and_quota_failures_on_a_state_call_are_not_skipped(sdk: SdkMock, status: int) -> None:
    sdk.add("GET", STATE_URL.format("DH-1"), status=status, payload={}, repeat=True)
    sdk.serve([LEGACY_AC, DEHUMIDIFIER])

    with pytest.raises((AuthenticationError, QuotaExceededError)):
        await make_backend().fetch_records()


async def test_list_failure_raises(sdk: SdkMock) -> None:
    sdk.add("GET", APPLIANCES_URL, status=500, payload={"error": "boom"})

    with pytest.raises(FrigidaireException) as err:
        await make_backend().fetch_records()
    assert type(err.value) is FrigidaireException
    assert err.value.status_code == 500


async def test_send_puts_one_property(sdk: SdkMock) -> None:
    sdk.serve([LEGACY_AC])

    await make_backend().send("AC-LEGACY-1", "mode", Mode.COOL)

    (call,) = sdk.calls("PUT", COMMAND_URL.format("AC-LEGACY-1"))
    assert call.kwargs["json"] == {"mode": "COOL"}
    assert type(call.kwargs["json"]["mode"]) is str


async def test_connect_and_account_email(sdk: SdkMock) -> None:
    sdk.serve([LEGACY_AC], email="Someone@Example.com")
    backend = make_backend(user_agent="frigidaire-test/1.0")

    await backend.connect()
    assert await backend.account_email() == "Someone@Example.com"

    (call,) = sdk.calls("GET", APPLIANCES_URL)
    assert call.kwargs["headers"]["Authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert call.kwargs["headers"]["x-api-key"] == API_KEY
    assert call.kwargs["headers"]["User-Agent"].startswith("frigidaire-test/1.0 ")


def test_repr_holds_no_secrets() -> None:
    assert API_KEY not in repr(make_backend()) and REFRESH_TOKEN not in repr(make_backend())


# --- tokens ---


async def test_rotated_tokens_reach_on_tokens(sdk: SdkMock) -> None:
    rotated = make_jwt(3600, subject="user-1-rotated")
    sdk.add("POST", REFRESH_URL, payload={"accessToken": rotated, "refreshToken": "refresh-SECRET-2"})
    sdk.serve([LEGACY_AC])
    seen: list[tuple[str, str]] = []
    backend = make_backend(make_jwt(30), on_tokens=lambda access, refresh: seen.append((access, refresh)))
    assert seen == []  # never at construction

    await backend.fetch_records()
    await backend.fetch_records()

    assert seen == [(rotated, "refresh-SECRET-2")]
    assert backend.tokens == (rotated, "refresh-SECRET-2")
    (refresh_call,) = sdk.calls("POST", REFRESH_URL)
    assert refresh_call.kwargs["json"] == {"refreshToken": REFRESH_TOKEN}
    for call in sdk.calls("GET", APPLIANCES_URL):
        assert call.kwargs["headers"]["Authorization"] == f"Bearer {rotated}"


async def test_concurrent_requests_spend_the_refresh_token_once(sdk: SdkMock) -> None:
    # Registered once: a second refresh would find no response and fail.
    sdk.add("POST", REFRESH_URL, payload={"accessToken": make_jwt(3600), "refreshToken": "refresh-SECRET-2"})
    sdk.serve([LEGACY_AC, DEHUMIDIFIER])
    seen: list[tuple[str, str]] = []
    backend = make_backend(make_jwt(30), on_tokens=lambda access, refresh: seen.append((access, refresh)))

    await asyncio.gather(backend.account_email(), backend.connect(), backend.fetch_record("DH-1"))

    assert len(seen) == 1
    assert len(sdk.calls("POST", REFRESH_URL)) == 1


async def test_failing_token_callback_keeps_the_new_tokens(sdk: SdkMock, caplog: pytest.LogCaptureFixture) -> None:
    rotated = make_jwt(3600)
    sdk.add("POST", REFRESH_URL, payload={"accessToken": rotated, "refreshToken": "refresh-SECRET-2"})
    sdk.serve([LEGACY_AC])

    def broken(access: str, refresh: str) -> None:
        raise OSError(f"disk full writing {refresh}")

    backend = make_backend(make_jwt(30), on_tokens=broken)
    await backend.fetch_records()

    assert backend.tokens == (rotated, "refresh-SECRET-2")
    assert "token callback failed (OSError)" in caplog.text
    assert "refresh-SECRET-2" not in caplog.text


async def test_rejected_refresh_is_an_authentication_error(sdk: SdkMock) -> None:
    sdk.add("POST", REFRESH_URL, status=400, payload={"error": "invalid_grant", "detail": "SECRET-BODY"}, repeat=True)
    sdk.serve([LEGACY_AC])
    backend = make_backend(make_jwt(30))

    for call in (backend.connect, backend.fetch_records, backend.account_email):
        with pytest.raises(AuthenticationError) as err:
            await call()
        assert "SECRET" not in str(err.value)


@pytest.mark.parametrize(
    "failure",
    [
        {"exception": aiohttp.ClientConnectionError("unreachable")},
        {"exception": asyncio.TimeoutError()},
        {"status": 503, "payload": {"detail": "SECRET-BODY"}},
        {"status": 502, "body": "<html>SECRET-BODY</html>", "content_type": "application/json"},
    ],
    ids=["unreachable", "timeout", "server-error", "no-status"],
)
async def test_refresh_without_a_verdict_is_transient_and_keeps_the_refresh_token(
    sdk: SdkMock, failure: dict[str, Any]
) -> None:
    rotated = make_jwt(3600)
    sdk.add("POST", REFRESH_URL, **failure)
    sdk.add("POST", REFRESH_URL, payload={"accessToken": rotated, "refreshToken": "refresh-SECRET-2"})
    sdk.serve([LEGACY_AC])
    seen: list[tuple[str, str]] = []
    backend = make_backend(make_jwt(30), on_tokens=lambda access, refresh: seen.append((access, refresh)))

    with pytest.raises(FrigidaireException) as err:
        await backend.connect()
    assert type(err.value) is FrigidaireException
    assert "SECRET" not in str(err.value)
    assert seen == []

    await backend.connect()  # the next attempt refreshes with the same refresh token
    assert seen == [(rotated, "refresh-SECRET-2")]
    assert [c.kwargs["json"] for c in sdk.calls("POST", REFRESH_URL)] == [{"refreshToken": REFRESH_TOKEN}] * 2


@pytest.mark.parametrize("status", [400, 401, 403])
@pytest.mark.parametrize("operation", ["connect", "fetch_records", "account_email", "fetch_record", "send"])
async def test_refresh_rejected_by_the_token_endpoint_carries_its_status(
    sdk: SdkMock, status: int, operation: str
) -> None:
    sdk.add("POST", REFRESH_URL, status=status, payload={"detail": "SECRET-BODY"}, repeat=True)
    sdk.serve([LEGACY_AC])
    backend = make_backend(make_jwt(30))
    backend._appliances = {"AC-LEGACY-1": list_item(LEGACY_AC)}

    with pytest.raises(AuthenticationError) as err:
        await OPERATIONS[operation][2](backend)
    assert err.value.status_code == status
    assert "SECRET" not in str(err.value)


async def test_refresh_hitting_the_quota_is_quota_exceeded(sdk: SdkMock) -> None:
    sdk.add("POST", REFRESH_URL, status=429, headers={"Retry-After": "30"}, repeat=True)
    sdk.serve([LEGACY_AC])

    with pytest.raises(QuotaExceededError) as err:
        await make_backend(make_jwt(30)).fetch_records()
    assert err.value.retry_after == 30.0


async def test_access_token_that_is_not_a_jwt_is_an_authentication_error(sdk: SdkMock) -> None:
    sdk.serve([LEGACY_AC])

    with pytest.raises(AuthenticationError):
        await make_backend("not-a-jwt").fetch_records()


async def test_tokens_and_auth_bodies_stay_out_of_logs(sdk: SdkMock, caplog: pytest.LogCaptureFixture) -> None:
    rotated = make_jwt(3600, subject="rotated-SECRET")
    sdk.add("POST", REFRESH_URL, payload={"accessToken": rotated, "refreshToken": "refresh-SECRET-2"})
    sdk.add("POST", REFRESH_URL, status=400, payload={"error": "SECRET-BODY"}, repeat=True)
    sdk.serve([LEGACY_AC])
    caplog.set_level(logging.DEBUG)

    await make_backend(make_jwt(30)).fetch_records()
    with pytest.raises(AuthenticationError):
        await make_backend(make_jwt(30)).fetch_records()

    assert "Response from" in caplog.text  # the SDK's debug logging ran
    for secret in (rotated, "refresh-SECRET-2", REFRESH_TOKEN, API_KEY, "SECRET-BODY"):
        assert secret not in caplog.text


async def test_response_bodies_and_sdk_error_text_stay_out_of_logs(
    sdk: SdkMock, caplog: pytest.LogCaptureFixture
) -> None:
    # Appliance endpoints: an auth failure, a server error and a quota failure, each with a body.
    sdk.add("GET", APPLIANCES_URL, status=401, payload={"detail": "BODY-401-MARKER"})
    sdk.add("GET", EMAIL_URL, status=403, payload={"detail": "BODY-403-MARKER"})
    sdk.add("GET", STATE_URL.format("DH-1"), status=500, payload={"detail": "BODY-500-MARKER"})
    sdk.add("PUT", COMMAND_URL.format("DH-1"), status=429, body="BODY-429-MARKER", repeat=True)
    # Successful bodies: the account email and serial numbers.
    sdk.serve([LEGACY_AC, DEHUMIDIFIER], email="private-MARKER@example.com")
    # The stream: its URL, and a payload the SDK cannot decode.
    sdk.add(
        "GET",
        STREAM_URL,
        body=b"data: not-json-MARKER\n\n",
        content_type="text/event-stream",
        response_class=_StreamResponse,
    )
    caplog.set_level(logging.DEBUG)
    backend = make_backend()

    with pytest.raises(AuthenticationError):
        await backend.connect()
    with pytest.raises(AuthenticationError):
        await backend.account_email()
    assert await backend.account_email() == "private-MARKER@example.com"
    await backend.fetch_records()  # DH-1 is skipped
    with pytest.raises(QuotaExceededError):
        await backend.send("DH-1", "targetHumidity", 50)
    backend.stream_initial_backoff = 60
    task = asyncio.create_task(backend.listen(lambda r: None, lambda: None, lambda: None))
    await _wait_for(lambda: "Reconnecting SSE stream" in caplog.text)
    await _stop(task)

    for logged in ("Response from", "Test connection failed", "Failed to decode SSE JSON"):
        assert logged in caplog.text  # the SDK did log
    for secret in ("MARKER", "SN-AC-LEGACY-1", STREAM_URL, API_KEY, ACCESS_TOKEN, REFRESH_TOKEN):
        assert secret not in caplog.text


# --- error mapping ---

OPERATIONS: dict[str, tuple[str, str, Callable[[ApiKeyBackend], Any]]] = {
    "connect": ("GET", APPLIANCES_URL, lambda b: b.connect()),
    "account_email": ("GET", EMAIL_URL, lambda b: b.account_email()),
    "fetch_records": ("GET", APPLIANCES_URL, lambda b: b.fetch_records()),
    "fetch_record": ("GET", STATE_URL.format("AC-LEGACY-1"), lambda b: b.fetch_record("AC-LEGACY-1")),
    "send": ("PUT", COMMAND_URL.format("AC-LEGACY-1"), lambda b: b.send("AC-LEGACY-1", "targetHumidity", 50)),
}


async def _fail(sdk: SdkMock, operation: str, **response: Any) -> FrigidaireException:
    method, url, call = OPERATIONS[operation]
    if operation in ("fetch_record", "send"):
        sdk.add("GET", APPLIANCES_URL, payload=[list_item(LEGACY_AC)], repeat=True)
        sdk.add("GET", INFO_URL.format("AC-LEGACY-1"), payload=info_payload(LEGACY_AC), repeat=True)
    sdk.add(method, url, repeat=True, **response)
    with pytest.raises(FrigidaireException) as err:
        await call(make_backend())
    for secret in ("SECRET-BODY", API_KEY, ACCESS_TOKEN, REFRESH_TOKEN):
        assert secret not in str(err.value)
    return err.value


@pytest.mark.parametrize("operation", list(OPERATIONS))
@pytest.mark.parametrize("status", [401, 403])
async def test_rejected_credentials_are_authentication_errors(sdk: SdkMock, operation: str, status: int) -> None:
    error = await _fail(sdk, operation, status=status, payload={"detail": "SECRET-BODY"})
    assert isinstance(error, AuthenticationError)


@pytest.mark.parametrize("operation", list(OPERATIONS))
async def test_quota_after_the_sdk_retries_is_quota_exceeded(sdk: SdkMock, operation: str) -> None:
    error = await _fail(sdk, operation, status=429, headers={"Retry-After": "30"}, body="SECRET-BODY")
    assert isinstance(error, QuotaExceededError)
    assert error.retry_after == 30.0
    assert error.status_code == 429
    method, url, _ = OPERATIONS[operation]
    assert len(sdk.calls(method, url)) == 3  # the SDK's own attempts


async def test_quota_retry_after_as_a_date(sdk: SdkMock) -> None:
    when = datetime.now(timezone.utc) + timedelta(seconds=120)
    error = await _fail(sdk, "fetch_records", status=429, headers={"Retry-After": format_datetime(when, usegmt=True)})
    assert isinstance(error, QuotaExceededError)
    assert error.retry_after is not None and 100 < error.retry_after <= 120


async def test_quota_without_retry_after(sdk: SdkMock) -> None:
    error = await _fail(sdk, "fetch_records", status=429)
    assert isinstance(error, QuotaExceededError) and error.retry_after is None


@pytest.mark.parametrize("operation", ["send", "fetch_record"])
async def test_406_is_command_rejected(sdk: SdkMock, operation: str) -> None:
    error = await _fail(sdk, operation, status=406, payload={"detail": "SECRET-BODY"})
    assert isinstance(error, CommandRejectedError)
    assert error.status_code == 406


@pytest.mark.parametrize("operation", list(OPERATIONS))
async def test_other_statuses_are_frigidaire_exceptions(sdk: SdkMock, operation: str) -> None:
    error = await _fail(sdk, operation, status=500, payload={"detail": "SECRET-BODY"})
    assert type(error) is FrigidaireException
    assert error.status_code == 500


@pytest.mark.parametrize("operation", list(OPERATIONS))
async def test_missing_status_is_a_frigidaire_exception(sdk: SdkMock, operation: str) -> None:
    # A body that claims to be JSON but is not: the SDK drops the HTTP status.
    error = await _fail(sdk, operation, status=401, body="<html>SECRET-BODY</html>", content_type="application/json")
    assert type(error) is FrigidaireException
    assert error.status_code is None
    assert "no HTTP status" in str(error)


@pytest.mark.parametrize("operation", list(OPERATIONS))
async def test_non_json_error_body_keeps_its_status(sdk: SdkMock, operation: str) -> None:
    error = await _fail(sdk, operation, status=403, body="<html>SECRET-BODY</html>", content_type="text/html")
    assert isinstance(error, AuthenticationError)


@pytest.mark.parametrize("operation", list(OPERATIONS))
async def test_network_failure_is_a_frigidaire_exception(sdk: SdkMock, operation: str) -> None:
    error = await _fail(sdk, operation, exception=aiohttp.ClientConnectionError("unreachable"))
    assert type(error) is FrigidaireException
    assert error.status_code is None


# --- event stream ---


async def _stop(task: asyncio.Task[None]) -> None:
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_stream_events_are_applied_to_records(sdk: SdkMock) -> None:
    sdk.serve([LEGACY_AC, DEHUMIDIFIER])
    sdk.stream(
        {"applianceId": "AC-LEGACY-1", "property": "mode", "value": "HEAT"},
        {"applianceId": "NOT-ON-ACCOUNT", "property": "mode", "value": "COOL"},
        {"applianceId": "DH-1", "property": "targetHumidity", "value": 50},
        {"applianceId": "AC-LEGACY-1", "property": "networkInterface/rssi", "value": -40},
        {"applianceId": "AC-LEGACY-1", "property": "connectionState", "value": "Disconnected"},
    )
    backend = make_backend()
    backend.stream_initial_backoff = 60  # stay disconnected once the stream body ends
    records: list[dict] = []
    events: list[str] = []
    task = asyncio.create_task(
        backend.listen(records.append, lambda: events.append("connect"), lambda: events.append("disconnect"))
    )
    await _wait_for(lambda: events == ["connect", "disconnect"])

    assert [r["applianceId"] for r in records] == ["AC-LEGACY-1", "DH-1", "AC-LEGACY-1", "AC-LEGACY-1"]
    heat, humidity, rssi, disconnected = records
    assert Appliance(heat).mode == Mode.HEAT
    assert heat["properties"]["reported"] == {**LEGACY_AC["properties"]["reported"], "mode": "HEAT"}
    assert heat["applianceData"]["applianceInfo"]["serialNumber"] == "SN-AC-LEGACY-1"
    assert Appliance(humidity).target_humidity == 50
    assert rssi["properties"]["reported"]["mode"] == "HEAT"  # events build on each other
    assert rssi["properties"]["reported"]["networkInterface"] == {"rssi": -40}
    assert disconnected["connectionState"] == "Disconnected"
    assert Appliance(disconnected).is_connected is False

    # A resync replaces the raw state the next events build on.
    resynced = await backend.fetch_record("AC-LEGACY-1")
    assert resynced["properties"]["reported"]["mode"] == "COOL"
    await _stop(task)
    assert events == ["connect", "disconnect"]


async def test_stream_reconnects_and_reports_each_connection(sdk: SdkMock) -> None:
    sdk.serve([LEGACY_AC])
    sdk.stream({"applianceId": "AC-LEGACY-1", "property": "mode", "value": "HEAT"})
    sdk.stream({"applianceId": "AC-LEGACY-1", "property": "mode", "value": "ECO"})
    backend = make_backend()
    backend.stream_initial_backoff = 0.01
    backend.stream_max_backoff = 0.05
    records: list[dict] = []
    events: list[str] = []
    task = asyncio.create_task(
        backend.listen(records.append, lambda: events.append("connect"), lambda: events.append("disconnect"))
    )
    await _wait_for(lambda: len(records) == 2 and events[-1:] == ["disconnect"])

    assert events == ["connect", "disconnect", "connect", "disconnect"]
    assert [Appliance(r).mode for r in records] == [Mode.HEAT, Mode.ECO]
    await _stop(task)
    assert events == ["connect", "disconnect", "connect", "disconnect"]  # no disconnect without a connect


async def test_stream_with_rejected_tokens_raises_authentication_error(sdk: SdkMock) -> None:
    sdk.add("GET", LIVESTREAM_URL, status=401, payload={"detail": "SECRET-BODY"}, repeat=True)
    sdk.serve([LEGACY_AC])
    backend = make_backend()
    events: list[str] = []

    with pytest.raises(AuthenticationError):
        await asyncio.wait_for(
            backend.listen(lambda r: None, lambda: events.append("connect"), lambda: events.append("disconnect")), 5
        )
    assert events == []


async def test_stream_stops_listening_when_cancelled_or_closed(sdk: SdkMock) -> None:
    sdk.serve([LEGACY_AC])
    sdk.stream(STREAM_EVENT)
    backend = make_backend()
    backend.stream_initial_backoff = 60
    connected = asyncio.Event()
    task = asyncio.create_task(backend.listen(lambda r: None, connected.set, lambda: None))
    await asyncio.wait_for(connected.wait(), 5)
    assert backend._client._sse_listeners

    await _stop(task)
    assert not backend._client._sse_listeners
    await backend.close()


async def test_stream_answering_with_an_http_error_never_counts_as_connected(sdk: SdkMock) -> None:
    # The SDK runs its opening callbacks before it looks at the response and hides the status.
    sdk.serve([LEGACY_AC])
    for _ in range(3):
        sdk.add("GET", STREAM_URL, status=401, payload={"detail": "SECRET-BODY"})
    backend = make_backend()
    backend.stream_initial_backoff = 0.01
    backend.stream_max_backoff = 0.02
    backend.stream_confirm_after = 0.05
    events: list[str] = []
    task = asyncio.create_task(
        backend.listen(lambda r: None, lambda: events.append("connect"), lambda: events.append("disconnect"))
    )
    await _wait_for(lambda: len(sdk.calls("GET", STREAM_URL)) >= 3)
    await asyncio.sleep(0.1)  # past stream_confirm_after

    assert events == []
    assert not task.done()  # still reconnecting, with backoff
    await _stop(task)
    assert events == []


async def test_stream_that_stays_open_without_events_counts_as_connected(sdk: SdkMock) -> None:
    sdk.serve([LEGACY_AC])
    sdk.stream(stay_open=True)
    backend = make_backend()
    backend.stream_confirm_after = 0.05
    events: list[str] = []
    task = asyncio.create_task(
        backend.listen(lambda r: None, lambda: events.append("connect"), lambda: events.append("disconnect"))
    )
    await _wait_for(lambda: events == ["connect"])

    await _stop(task)
    assert events == ["connect", "disconnect"]


async def test_first_stream_event_counts_as_connected_before_it_is_delivered(sdk: SdkMock) -> None:
    sdk.serve([LEGACY_AC])
    sdk.stream({"applianceId": "AC-LEGACY-1", "property": "mode", "value": "HEAT"}, stay_open=True)
    backend = make_backend()
    backend.stream_confirm_after = 60
    events: list[str] = []
    task = asyncio.create_task(
        backend.listen(
            lambda r: events.append(f"record {Appliance(r).mode}"),
            lambda: events.append("connect"),
            lambda: events.append("disconnect"),
        )
    )
    await _wait_for(lambda: len(events) == 2)

    assert events == ["connect", f"record {Mode.HEAT}"]
    await _stop(task)


async def test_stream_keeps_reconnecting_through_a_network_failure_while_refreshing(sdk: SdkMock) -> None:
    sdk.add("POST", REFRESH_URL, exception=aiohttp.ClientConnectionError("unreachable"), repeat=True)
    sdk.serve([LEGACY_AC])
    backend = make_backend()
    await backend.fetch_records()  # with a valid token; then it expires
    backend._token_manager._auth_data = backend._token_manager._auth_data.__class__(
        make_jwt(30), REFRESH_TOKEN, API_KEY
    )
    backend.stream_initial_backoff = 0.01
    backend.stream_max_backoff = 0.02
    task = asyncio.create_task(backend.listen(lambda r: None, lambda: None, lambda: None))
    await _wait_for(lambda: len(sdk.calls("POST", REFRESH_URL)) >= 2)

    assert not task.done()  # a refresh that got no answer is not rejected tokens
    await _stop(task)


async def _wait_for(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.01)
