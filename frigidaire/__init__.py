"""Python API for Frigidaire air conditioners and dehumidifiers.

Public exports only. Two clients share one appliance model and the same command plans:

- ``AsyncFrigidaire(backend)``, the async client, over any :class:`Backend`: ``PasswordBackend``
  (email and password) or ``ApiKeyBackend`` (the official API, beta)::

      client = AsyncFrigidaire(PasswordBackend("email", "password"))
      await client.connect()
      appliances = await client.get_appliances()

- ``Frigidaire(username, password, ...)``, the synchronous client of 1.x, unchanged::

      client = Frigidaire("email", "password")
      appliances = client.get_appliances()
"""

from __future__ import annotations

from .backends.api_key import ApiKeyBackend
from .backends.base import Backend
from .client import AsyncFrigidaire
from .exceptions import (
    AuthenticationError,
    CommandRejectedError,
    FrigidaireException,
    LoginError,
    QuotaExceededError,
    SessionCapError,
)
from .model import (
    Action,
    Alert,
    Appliance,
    ApplianceState,
    CaseInsensitiveEnum,
    Component,
    ConnectionState,
    Destination,
    Detail,
    DisplayLight,
    FanSpeed,
    FilterState,
    Mode,
    Power,
    Setting,
    SleepMode,
    Unit,
    VerticalSwing,
)

# isort: split
# --- The email-and-password backend and the 1.x sync client built on it. This block, the alias
# modules and the names in __all__ below go when backends/password is deleted.
from .backends.password import JsonFileSessionStore, PasswordBackend, SessionStore
from .backends.password.sync_client import Frigidaire

# isort: split
# Names this module held in 1.0, before the password code moved to backends/password. Kept so
# old imports and patches (for example ``frigidaire.time.sleep``) still work; not public API.
import time as time

from . import rate_limit as rate_limit, session_store as session_store, signature_generator as signature_generator
from .backends.password.rate_limit import RateLimiter as RateLimiter, wrap_session_request as wrap_session_request
from .backends.password.signature_generator import get_signature as get_signature
from .backends.password.transport import (
    _SCOPED_LIMITERS as _SCOPED_LIMITERS,
    _SCOPED_REAUTH_LOCKS as _SCOPED_REAUTH_LOCKS,
    AUTH_USER_AGENT as AUTH_USER_AGENT,
    CLIENT_ID as CLIENT_ID,
    CLIENT_SECRET as CLIENT_SECRET,
    FRIGIDAIRE_API_KEY as FRIGIDAIRE_API_KEY,
    FRIGIDAIRE_USER_AGENT as FRIGIDAIRE_USER_AGENT,
    GLOBAL_API_URL as GLOBAL_API_URL,
    SESSION_CAP_ERROR_CODE as SESSION_CAP_ERROR_CODE,
    _redact_headers as _redact_headers,
    _redact_payload as _redact_payload,
)

__all__ = [
    "Action",
    "Alert",
    "ApiKeyBackend",
    "Appliance",
    "ApplianceState",
    "AsyncFrigidaire",
    "AuthenticationError",
    "Backend",
    "CaseInsensitiveEnum",
    "CommandRejectedError",
    "Component",
    "ConnectionState",
    "Destination",
    "Detail",
    "DisplayLight",
    "FanSpeed",
    "FilterState",
    "FrigidaireException",
    "LoginError",
    "Mode",
    "Power",
    "QuotaExceededError",
    "SessionCapError",
    "Setting",
    "SleepMode",
    "Unit",
    "VerticalSwing",
    # the password backend
    "Frigidaire",
    "JsonFileSessionStore",
    "PasswordBackend",
    "SessionStore",
]
