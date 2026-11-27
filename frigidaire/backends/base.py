"""The protocol every backend implements, and the internal record format they exchange.

Internal record format
======================

Every backend speaks in records of one shape, the appliance-list record of the Frigidaire 2.0
API. :class:`~frigidaire.model.Appliance` parses it, so a record from any backend becomes the
same snapshot::

    {
        "applianceId": "AC-123",                  # str, required: stable id used for commands
        "applianceData": {
            "modelName": "AC",                    # str, required: the appliance type ("AC", "DH", "Husky", ...)
            "applianceName": "Bedroom AC",        # str, required: the user's nickname
            ...                                   # anything else the backend knows, passed through
        },
        "properties": {
            "reported": {                         # dict: the latest reported state, wire keys and values
                "applianceState": "running",      #   as the firmware sends them (either casing)
                "mode": "cool",
                ...
            }
        },
        "connectionState": "Connected",           # str, optional: "Connected" or "Disconnected"
        ...                                       # any other top-level keys, passed through
    }

A record is a plain, JSON-compatible ``dict``. Backends return a fresh copy on every call, so a
caller may keep or mutate it. A record whose required keys are missing is malformed; the client
skips it with a warning rather than failing the whole fetch.

Errors
======

Backends raise only the library's exceptions (:mod:`frigidaire.exceptions`):

- ``AuthenticationError`` when the credentials or tokens are rejected and new ones are needed.
- ``LoginError`` for any other failed login, ``SessionCapError`` for the password backend's
  active-session cap.
- ``QuotaExceededError`` when the request quota is used up, with a ``retry_after`` hint.
- ``CommandRejectedError`` when an appliance refuses a command in its current state.
- ``FrigidaireException`` for anything else.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

RecordCallback = Callable[[dict], None]
"""Receives one appliance's full, updated record."""

ConnectionCallback = Callable[[], None]
"""Called when the live-update stream connects or disconnects."""


@runtime_checkable
class Backend(Protocol):
    """How the :class:`~frigidaire.client.AsyncFrigidaire` client reaches an account.

    Every method is a coroutine and must not block the event loop.
    """

    supports_live_updates: bool
    """Whether :meth:`listen` pushes updates. When ``False``, callers poll :meth:`fetch_records`."""

    async def connect(self) -> None:
        """Log in, or validate the stored session or tokens."""

    async def account_email(self) -> str:
        """The email address of the signed-in account."""

    async def fetch_records(self) -> list[dict]:
        """Every appliance on the account, as internal records."""

    async def fetch_record(self, appliance_id: str) -> dict:
        """One appliance's current internal record. Raises ``FrigidaireException`` for an unknown id."""

    async def send(self, appliance_id: str, key: str, value: Any) -> None:
        """Send one property to one appliance, in one request."""

    async def listen(
        self,
        on_record: RecordCallback,
        on_connect: ConnectionCallback,
        on_disconnect: ConnectionCallback,
    ) -> None:
        """Stream live updates until cancelled, passing each appliance's full updated record to
        ``on_record``. Calls ``on_connect`` each time the stream (re)connects, once it is known to
        deliver, and ``on_disconnect`` each time a connected stream drops; an attempt that fails
        before delivering calls neither. Raises ``NotImplementedError`` when
        ``supports_live_updates`` is ``False``."""

    async def close(self) -> None:
        """Release connections. The backend is not used afterwards."""
