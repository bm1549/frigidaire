"""Helpers for the API key backend's tests: ``aioresponses`` at the official SDK's own URLs.

Only tests under ``tests/api_key`` use them, so deleting the API key backend deletes them too.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
import time
from collections.abc import Callable
from typing import Any
from unittest import mock

import jwt
from aiohttp import ClientResponse
from aioresponses import aioresponses
from electrolux_group_developer_sdk.client import client_util
from electrolux_group_developer_sdk.client.rate_limiter import RateLimiter

from frigidaire import ApiKeyBackend

API = "https://api.developer.electrolux.one/api/v1"
APPLIANCES_URL = f"{API}/appliances"
INFO_URL = f"{API}/appliances/{{}}/info"
STATE_URL = f"{API}/appliances/{{}}/state"
COMMAND_URL = f"{API}/appliances/{{}}/command"
EMAIL_URL = f"{API}/users/current/email"
REFRESH_URL = f"{API}/token/refresh"
LIVESTREAM_URL = f"{API}/configurations/livestream"
STREAM_URL = "https://stream.example.test/v1/events"

API_KEY = "api-key-SECRET"
REFRESH_TOKEN = "refresh-SECRET-1"
CREATED = "2024-05-01T12:00:00Z"


def make_jwt(expires_in: float, subject: str = "user-1") -> str:
    """An access token that expires ``expires_in`` seconds from now. The SDK refreshes within 60s."""
    return jwt.encode({"sub": subject, "exp": int(time.time() + expires_in)}, "k" * 32, algorithm="HS256")


ACCESS_TOKEN = make_jwt(3600)

# aioresponses 0.7.9 builds responses without the stream_writer that aiohttp 3.14 requires.
_NEEDS_STREAM_WRITER = "stream_writer" in inspect.signature(ClientResponse.__init__).parameters


class _Response(ClientResponse):
    def __init__(self, method: str, url: Any, **kwargs: Any) -> None:
        if _NEEDS_STREAM_WRITER:
            kwargs.setdefault("stream_writer", mock.Mock(output_size=0))
        super().__init__(method, url, **kwargs)


class _StreamResponse(_Response):
    """An event stream that stays open until its body is read; aioresponses marks bodies closed."""

    @property
    def closed(self) -> bool:
        return False


class _HeldOpen:
    """A response body that, once read, waits for more instead of ending."""

    def __init__(self, reader: Any) -> None:
        self._reader = reader

    def __getattr__(self, name: str) -> Any:
        return getattr(self._reader, name)

    async def readline(self) -> bytes:
        line: bytes = await self._reader.readline()
        if not line:
            await asyncio.Event().wait()  # until the reader is cancelled
        return line


class _OpenStreamResponse(_StreamResponse):
    """An event stream that sends its body and then stays open, sending nothing more."""

    @property  # type: ignore[override]
    def content(self) -> Any:
        return self._held_open

    @content.setter
    def content(self, reader: Any) -> None:
        self._held_open = _HeldOpen(reader)


def list_item(record: dict) -> dict:
    return {
        "applianceId": record["applianceId"],
        "applianceName": record["applianceData"]["applianceName"],
        "applianceType": record["applianceData"]["modelName"],
        "created": CREATED,
    }


def info_payload(record: dict) -> dict:
    return {
        "applianceInfo": {
            "serialNumber": f"SN-{record['applianceId']}",
            "pnc": "950011538",
            "brand": "FRIGIDAIRE",
            "deviceType": "PORTABLE_AIR_CONDITIONER",
            "model": "FHPC102AB1",
            "variant": "A1",
            "colour": "WHITE",
        },
        "capabilities": {"mode": {"access": "readwrite", "type": "string", "values": {"COOL": {}, "DRY": {}}}},
    }


def state_payload(record: dict) -> dict:
    return {
        "applianceId": record["applianceId"],
        "connectionState": record.get("connectionState", "Connected"),
        "status": record.get("status", "enabled"),
        "properties": {"reported": copy.deepcopy(record["properties"]["reported"])},
    }


def sse(*events: dict) -> bytes:
    return b"".join(f"data: {json.dumps(event)}\n\n".encode() for event in events)


class SdkMock:
    """``aioresponses`` at the SDK's URLs, with the SDK's rate limiter and retry backoff disabled.

    Matchers are tried in the order they were added, so register a failure before ``serve``.
    """

    def __init__(self) -> None:
        self.responses = aioresponses()
        self.sent: list[tuple[str, str, object]] = []
        self._patches = [
            mock.patch.object(client_util, "rate_limiter", RateLimiter(max_calls=1_000_000, period=1.0)),
            mock.patch.object(client_util, "INITIAL_BACKOFF", 0),
        ]

    def start(self) -> SdkMock:
        for patch in self._patches:
            patch.start()
        self.responses.start()
        return self

    def stop(self) -> None:
        self.responses.stop()
        for patch in reversed(self._patches):
            patch.stop()

    def add(self, method: str, url: str, **kwargs: Any) -> None:
        kwargs.setdefault("response_class", _Response)
        self.responses.add(url, method, **kwargs)

    def serve(self, records: list[dict], *, email: str = "user@example.com") -> None:
        """Serve these internal records through the list, info, state and command calls."""
        self.add("GET", APPLIANCES_URL, payload=[list_item(r) for r in records], repeat=True)
        self.add("GET", EMAIL_URL, payload={"email": email}, repeat=True)
        for record in records:
            appliance_id = record["applianceId"]
            self.add("GET", INFO_URL.format(appliance_id), payload=info_payload(record), repeat=True)
            self.add("GET", STATE_URL.format(appliance_id), payload=state_payload(record), repeat=True)
            self.add("PUT", COMMAND_URL.format(appliance_id), callback=self._command(appliance_id), repeat=True)
        self.add(
            "GET",
            LIVESTREAM_URL,
            payload={
                "url": STREAM_URL,
                "appliances": [{"applianceId": r["applianceId"], "properties": []} for r in records],
            },
            repeat=True,
        )

    def stream(self, *events: dict, stay_open: bool = False) -> None:
        """One connection of the event stream, which sends these events and then ends, or with
        ``stay_open`` stays open until the stream is cancelled."""
        self.add(
            "GET",
            STREAM_URL,
            body=sse(*events),
            content_type="text/event-stream",
            response_class=_OpenStreamResponse if stay_open else _StreamResponse,
        )

    def _command(self, appliance_id: str) -> Callable[..., None]:
        def record(url: Any, **kwargs: Any) -> None:
            ((key, value),) = kwargs["json"].items()
            self.sent.append((appliance_id, key, value))

        return record

    def calls(self, method: str, url: str) -> list[Any]:
        return [
            call
            for (call_method, call_url), calls in self.responses.requests.items()
            if call_method == method and str(call_url) == url
            for call in calls
        ]


def make_backend(access_token: str = ACCESS_TOKEN, **kwargs: Any) -> ApiKeyBackend:
    return ApiKeyBackend(API_KEY, access_token, REFRESH_TOKEN, **kwargs)


STREAM_EVENT = {"applianceId": "AC-LEGACY-1", "property": "mode", "value": "COOL"}
"""An event that leaves LEGACY_AC as it is: for tests that only need the stream to deliver data."""
