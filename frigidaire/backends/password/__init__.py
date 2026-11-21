"""The email-and-password backend: today's Frigidaire 2.0 app login, run on a worker thread.

Everything specific to this sign-in method lives in this package: the Gigya login, the session
store, the active-session cap handling, write throttling and the re-authentication lock. Shared
code never imports from it, so it can be deleted without touching anything else.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from ...exceptions import FrigidaireException
from ..base import ConnectionCallback, RecordCallback
from .session_store import JsonFileSessionStore, SessionStore
from .transport import PasswordTransport

if TYPE_CHECKING:
    from ..base import Backend

__all__ = ["JsonFileSessionStore", "PasswordBackend", "PasswordTransport", "SessionStore"]


class PasswordBackend:
    """Signs in with the account's email and password, and polls; there is no live stream.

    Wraps :class:`PasswordTransport` unchanged and runs each blocking call with
    ``asyncio.to_thread``. :meth:`connect` logs in (reusing a still-valid stored session); the
    other methods connect first if that has not happened yet.

    Keyword arguments are passed to :class:`PasswordTransport`; see it for the defaults.
    """

    supports_live_updates = False

    def __init__(
        self,
        username: str,
        password: str,
        *,
        session_key: str | None = None,
        regional_base_url: str | None = None,
        session_store: SessionStore | None = None,
        timeout: float | None = 15.0,
        country_code: str = "US",
        rate_limit_min_interval: float = 1.25,
        rate_limit_jitter: float = 0.25,
        rate_limit_methods: frozenset[str] | set[str] | None = None,
        rate_limit_scope_key: str | None = None,
        max_retries_on_429: int = 4,
        max_retry_after: float = 60.0,
        session_max_retries: int = 2,
        session_retry_backoff: float = 0.0,
    ) -> None:
        self.username = username
        self._password = password
        self._options: dict[str, Any] = {
            "session_key": session_key,
            "regional_base_url": regional_base_url,
            "session_store": session_store,
            "timeout": timeout,
            "country_code": country_code,
            "rate_limit_min_interval": rate_limit_min_interval,
            "rate_limit_jitter": rate_limit_jitter,
            "rate_limit_methods": rate_limit_methods,
            "rate_limit_scope_key": rate_limit_scope_key,
            "max_retries_on_429": max_retries_on_429,
            "max_retry_after": max_retry_after,
            "session_max_retries": session_max_retries,
            "session_retry_backoff": session_retry_backoff,
        }
        self._transport: PasswordTransport | None = None
        self._connect_lock = asyncio.Lock()

    def __repr__(self) -> str:
        return f"PasswordBackend(username={self.username!r})"

    @property
    def transport(self) -> PasswordTransport | None:
        """The signed-in transport, or ``None`` before :meth:`connect`."""
        return self._transport

    async def connect(self) -> None:
        async with self._connect_lock:
            if self._transport is None:
                self._transport = await asyncio.to_thread(
                    PasswordTransport, self.username, self._password, **self._options
                )
            else:
                await asyncio.to_thread(self._transport.authenticate)

    async def _connected(self) -> PasswordTransport:
        if self._transport is None:
            await self.connect()
        assert self._transport is not None
        return self._transport

    async def account_email(self) -> str:
        return self.username

    async def fetch_records(self) -> list[dict]:
        transport = await self._connected()
        return await asyncio.to_thread(transport.get_appliances_raw)

    async def fetch_record(self, appliance_id: str) -> dict:
        # The API has no single-appliance read; the full list is one request either way.
        for record in await self.fetch_records():
            if isinstance(record, dict) and record.get("applianceId") == appliance_id:
                return record
        raise FrigidaireException(f"Appliance {appliance_id} is not on the account")

    async def send(self, appliance_id: str, key: str, value: Any) -> None:
        transport = await self._connected()
        await asyncio.to_thread(transport.send_command, appliance_id, key, value)

    async def listen(
        self,
        on_record: RecordCallback,
        on_connect: ConnectionCallback,
        on_disconnect: ConnectionCallback,
    ) -> None:
        raise NotImplementedError("The password backend has no live updates; poll fetch_records instead")

    async def close(self) -> None:
        if self._transport is not None:
            await asyncio.to_thread(self._transport.close)


if TYPE_CHECKING:

    def _implements_backend(backend: PasswordBackend) -> Backend:
        return backend
