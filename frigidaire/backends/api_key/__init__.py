"""The API key backend: the official Electrolux Group developer API, through its SDK.

Everything specific to this sign-in method lives in this package, and this is the only module
that imports ``electrolux_group_developer_sdk``. Shared code never imports from it, so it can be
deleted without touching anything else.

The account is reached with three values from the Electrolux developer portal: an API key, an
access token and a refresh token. The SDK refreshes the access token shortly before it expires.
Refresh tokens are single-use, so every rotated pair is handed to ``on_tokens`` and must be
stored: the old refresh token no longer works.
"""

from __future__ import annotations

import asyncio
import contextlib
import email.utils
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, TypeVar

import jwt
from electrolux_group_developer_sdk.auth.auth_data import AuthData
from electrolux_group_developer_sdk.auth.invalid_credentials_exception import InvalidCredentialsException
from electrolux_group_developer_sdk.auth.invalid_token_exception import InvalidTokenException
from electrolux_group_developer_sdk.auth.token_manager import TokenManager
from electrolux_group_developer_sdk.auth.token_refresh_failed import TokenRefreshFailedException
from electrolux_group_developer_sdk.client.appliance_client import ApplianceClient, apply_sse_update
from electrolux_group_developer_sdk.client.bad_credentials_exception import BadCredentialsException
from electrolux_group_developer_sdk.client.dto.appliance_state import ApplianceState

from ...exceptions import AuthenticationError, CommandRejectedError, FrigidaireException, QuotaExceededError
from ..base import ConnectionCallback, RecordCallback
from .records import build_record

if TYPE_CHECKING:
    from ..base import Backend

__all__ = ["ApiKeyBackend", "TokenCallback"]

_LOGGER = logging.getLogger(__name__)

TokenCallback = Callable[[str, str], None]
"""Receives a rotated ``(access_token, refresh_token)`` pair."""

_T = TypeVar("_T")

# Exceptions in an SDK error's chain that mean the API key or tokens are no good.
_AUTH_ERRORS: tuple[type[BaseException], ...] = (
    BadCredentialsException,
    InvalidCredentialsException,
    InvalidTokenException,
    TokenRefreshFailedException,
    jwt.PyJWTError,  # an access token that is not a JWT
)


class _SdkLogRedactor(logging.Filter):
    """Keeps tokens and token-endpoint response bodies out of the SDK's own log lines.

    The SDK logs every response body at debug level, including the token refresh response that
    carries the new tokens, and logs refresh failures with the response body in the message.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.msg
        if not isinstance(msg, str):
            return True
        args = record.args
        if msg.startswith("Response from") and isinstance(args, tuple) and len(args) == 3:
            if "/token/" in str(args[0]):
                record.args = (args[0], args[1], "<redacted>")
        elif msg.startswith(("Error during token refresh", "Error during token revoke")) and isinstance(args, tuple):
            record.args = tuple(type(arg).__name__ if isinstance(arg, BaseException) else arg for arg in args)
        elif msg.startswith("Request failed after") and " Body: " in msg:
            record.msg = msg.split(" Body: ", 1)[0] + " Body: <redacted>"
        return True


_REDACTOR = _SdkLogRedactor()
for _name in ("electrolux_group_developer_sdk.client.client_util", "electrolux_group_developer_sdk.auth.token_manager"):
    _sdk_logger = logging.getLogger(_name)
    if _REDACTOR not in _sdk_logger.filters:
        _sdk_logger.addFilter(_REDACTOR)


class _TokenManager(TokenManager):
    """The SDK's token manager, with refreshes serialised.

    A refresh token works once. Without the lock, two requests that find the access token
    expired at the same moment would both refresh, and the second would fail.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._refresh_lock = asyncio.Lock()
        super().__init__(*args, **kwargs)

    async def get_auth_data(self) -> AuthData:
        async with self._refresh_lock:
            return await super().get_auth_data()


def _chain(exc: BaseException) -> list[BaseException]:
    """The exception and every exception it was raised from or while handling."""
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and current not in chain and len(chain) < 16:
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _status_of(exc: BaseException) -> int | None:
    for attr in ("status", "status_code"):
        value = getattr(exc, attr, None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _retry_after(chain: list[BaseException]) -> float | None:
    """The ``Retry-After`` hint of the first HTTP response in the chain that has one, in seconds."""
    for exc in chain:
        headers = getattr(exc, "headers", None)
        value = headers.get("Retry-After") if headers is not None and hasattr(headers, "get") else None
        if not value:
            continue
        try:
            return max(0.0, float(value))
        except (TypeError, ValueError):
            pass
        try:
            when = email.utils.parsedate_to_datetime(str(value))
        except (TypeError, ValueError, IndexError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
    return None


def _map_error(exc: BaseException, action: str) -> FrigidaireException:
    """The library error for an SDK failure.

    The SDK wraps HTTP errors in its own exceptions, sometimes keeping the status and sometimes
    only chaining the original error, and drops the status entirely when a response body is not
    JSON. So the whole chain is searched, and a missing status falls through to
    ``FrigidaireException``. Messages never include the SDK's, which can carry response bodies.
    """
    if isinstance(exc, FrigidaireException):
        return exc
    chain = _chain(exc)
    status = next((s for s in map(_status_of, chain) if s is not None), None)

    if status in (401, 403) or any(isinstance(e, _AUTH_ERRORS) for e in chain):
        return AuthenticationError(
            f"The Electrolux API rejected the API key or tokens ({action}); new ones are needed",
            status_code=status,
        )
    if status == 429:
        return QuotaExceededError(
            f"The Electrolux API request quota is used up ({action})",
            retry_after=_retry_after(chain),
            status_code=status,
        )
    if status == 406:
        return CommandRejectedError(
            f"The appliance refused the request in its current state ({action})", status_code=status
        )
    detail = f"HTTP {status}" if status is not None else "no HTTP status"
    return FrigidaireException(
        f"Electrolux API request failed ({action}): {type(chain[-1]).__name__}, {detail}", status_code=status
    )


async def _call(action: str, awaitable: Awaitable[_T]) -> _T:
    """Await an SDK call, raising only library errors."""
    try:
        return await awaitable
    except FrigidaireException:
        raise
    except Exception as exc:
        # Not chained: the SDK's exceptions can carry response bodies.
        raise _map_error(exc, action) from None


class ApiKeyBackend:
    """Signs in with an API key and token pair from the Electrolux developer portal.

    It has live updates: :meth:`listen` runs the SDK's event stream. Appliance info is fetched once
    per appliance and cached; a full fetch then costs one list call plus one state call per
    appliance.

    :param api_key: The developer portal API key.
    :param access_token: The access token (a JWT) issued with it.
    :param refresh_token: The refresh token issued with it. It works once.
    :param on_tokens: Called with ``(access_token, refresh_token)`` each time the tokens rotate,
        never at construction. Store the pair: the previous refresh token no longer works.
        Exceptions it raises are logged and otherwise ignored.
    :param user_agent: Prepended to the SDK's ``User-Agent``, to identify the caller.
    """

    supports_live_updates = True

    stream_initial_backoff: float = 1.0
    """Seconds before the event stream's first reconnection attempt; doubles on each failure."""
    stream_max_backoff: float = 120.0
    """The most seconds between event stream reconnection attempts."""

    def __init__(
        self,
        api_key: str,
        access_token: str,
        refresh_token: str,
        *,
        on_tokens: TokenCallback | None = None,
        user_agent: str | None = None,
    ) -> None:
        self._tokens = (access_token, refresh_token)
        self._on_tokens = on_tokens
        try:
            self._token_manager = _TokenManager(access_token, refresh_token, api_key, self._tokens_updated)
        except Exception as exc:
            raise _map_error(exc, "load the tokens") from None
        self._client = ApplianceClient(self._token_manager, external_user_agent=user_agent)
        self._appliances: dict[str, dict[str, Any]] = {}  # list items, by id, in list order
        self._info: dict[str, dict[str, Any]] = {}  # info calls, by id, cached for good
        self._states: dict[str, ApplianceState] = {}  # the raw SDK state, by id
        self._on_record: RecordCallback | None = None
        self._listeners: dict[str, Callable[[dict[str, Any]], None]] = {}

    def __repr__(self) -> str:
        return "ApiKeyBackend()"

    @property
    def tokens(self) -> tuple[str, str]:
        """The ``(access_token, refresh_token)`` pair in use now."""
        return self._tokens

    def _tokens_updated(self, access_token: str, refresh_token: str, api_key: str) -> None:
        # The SDK also calls this with the initial tokens; only a changed pair is a rotation.
        if (access_token, refresh_token) == self._tokens:
            return
        self._tokens = (access_token, refresh_token)
        if self._on_tokens is None:
            return
        try:
            self._on_tokens(access_token, refresh_token)
        except Exception as exc:
            # Raising here would make the SDK discard the new tokens after the old refresh
            # token was already spent.
            _LOGGER.error(
                "The token callback failed (%s); the new tokens are in use but were not saved", type(exc).__name__
            )

    # --- Backend protocol ---

    async def connect(self) -> None:
        await _call("test the connection", self._client.test_connection())

    async def account_email(self) -> str:
        email_address = await _call("read the account email", self._client.get_user_email())
        return email_address.email

    async def fetch_records(self) -> list[dict]:
        records = []
        for appliance_id in await self._list():
            await self._ensure_info(appliance_id)
            try:
                await self._fetch_state(appliance_id)
            except (AuthenticationError, QuotaExceededError):
                raise
            except FrigidaireException as exc:
                _LOGGER.warning("Skipping appliance %s: its state could not be read (%s)", appliance_id, exc)
                continue
            records.append(self._record(appliance_id))
        return records

    async def fetch_record(self, appliance_id: str) -> dict:
        if appliance_id not in self._appliances:
            await self._list()
            if appliance_id not in self._appliances:
                raise FrigidaireException(f"Appliance {appliance_id} is not on the account")
        await self._ensure_info(appliance_id)
        await self._fetch_state(appliance_id)
        return self._record(appliance_id)

    async def send(self, appliance_id: str, key: str, value: Any) -> None:
        if isinstance(value, Enum):
            value = value.value
        await _call(f"send {key} to {appliance_id}", self._client.send_command(appliance_id, {key: value}))

    async def listen(
        self,
        on_record: RecordCallback,
        on_connect: ConnectionCallback,
        on_disconnect: ConnectionCallback,
    ) -> None:
        """Run the SDK's event stream until cancelled, reconnecting with backoff when it drops.

        Each event is applied to the appliance's raw state with the SDK's ``apply_sse_update`` and
        the rebuilt record goes to ``on_record``. ``on_disconnect`` is called only after an
        ``on_connect``. Raises ``AuthenticationError`` when the stream fails because the API key or
        tokens were rejected; other failures reconnect.
        """
        if not self._states:
            await self.fetch_records()

        auth_failure: asyncio.Future[AuthenticationError] = asyncio.get_running_loop().create_future()
        connected = False

        async def opened() -> None:
            nonlocal connected
            connected = True
            on_connect()

        def closed(error: BaseException | None = None) -> None:
            nonlocal connected
            if connected:
                connected = False
                on_disconnect()
            if error is None or isinstance(error, asyncio.CancelledError) or auth_failure.done():
                return
            mapped = _map_error(error, "live updates")
            if isinstance(mapped, AuthenticationError):
                auth_failure.set_result(mapped)

        self._on_record = on_record
        for appliance_id in self._states:
            self._add_listener(appliance_id)
        stream = asyncio.ensure_future(
            self._client.start_event_stream(
                [opened],
                [closed],
                initial_backoff=self.stream_initial_backoff,
                max_backoff=self.stream_max_backoff,
            )
        )
        try:
            waiters: set[asyncio.Future[Any]] = {stream, auth_failure}
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
            if auth_failure.done():
                raise auth_failure.result()
            exc = stream.exception()
            if exc is not None:
                raise _map_error(exc, "live updates") from None
            raise FrigidaireException("The live update stream ended")
        finally:
            stream.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await stream
            self._remove_listeners()
            self._on_record = None

    async def close(self) -> None:
        self._remove_listeners()
        self._on_record = None

    # --- internals ---

    async def _list(self) -> list[str]:
        """Refresh the appliance list; returns the ids in list order."""
        appliances = await _call("list the appliances", self._client.get_appliances())
        self._appliances = {a.applianceId: a.model_dump(mode="json") for a in appliances}
        for appliance_id in set(self._states) - set(self._appliances):
            del self._states[appliance_id]
            self._remove_listener(appliance_id)
        for appliance_id in set(self._info) - set(self._appliances):
            del self._info[appliance_id]
        return list(self._appliances)

    async def _ensure_info(self, appliance_id: str) -> None:
        """Fetch and cache the appliance's info, once. A failure is retried on the next fetch."""
        if appliance_id in self._info:
            return
        try:
            details = await _call(f"read the info of {appliance_id}", self._client.get_appliance_details(appliance_id))
        except (AuthenticationError, QuotaExceededError):
            raise
        except FrigidaireException as exc:
            _LOGGER.warning("Could not read the info of appliance %s; will retry (%s)", appliance_id, exc)
            return
        self._info[appliance_id] = details.model_dump(mode="json")

    async def _fetch_state(self, appliance_id: str) -> None:
        state = await _call(f"read the state of {appliance_id}", self._client.get_appliance_state(appliance_id))
        self._states[appliance_id] = state
        self._add_listener(appliance_id)

    def _record(self, appliance_id: str) -> dict:
        return build_record(
            self._appliances[appliance_id],
            self._info.get(appliance_id),
            self._states[appliance_id].model_dump(mode="json"),
        )

    def _apply_event(self, appliance_id: str, event: dict[str, Any]) -> None:
        state = self._states.get(appliance_id)
        if state is None or appliance_id not in self._appliances:
            return
        self._states[appliance_id] = apply_sse_update(state, event)
        if self._on_record is not None:
            self._on_record(self._record(appliance_id))

    def _add_listener(self, appliance_id: str) -> None:
        """Listen for the appliance's events while :meth:`listen` runs."""
        if self._on_record is None or appliance_id in self._listeners:
            return

        def on_event(event: dict[str, Any]) -> None:
            self._apply_event(appliance_id, event)

        self._listeners[appliance_id] = on_event
        self._client.add_listener(appliance_id, on_event)

    def _remove_listener(self, appliance_id: str) -> None:
        callback = self._listeners.pop(appliance_id, None)
        if callback is not None:
            self._client.remove_listener(appliance_id, callback)

    def _remove_listeners(self) -> None:
        for appliance_id in list(self._listeners):
            self._remove_listener(appliance_id)


if TYPE_CHECKING:

    def _implements_backend(backend: ApiKeyBackend) -> Backend:
        return backend
