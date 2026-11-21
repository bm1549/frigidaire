"""Python API for Frigidaire air conditioners and dehumidifiers.

Public exports only. Start with :class:`Frigidaire` and a backend::

    client = Frigidaire(PasswordBackend("email", "password"))
    await client.connect()
    appliances = await client.get_appliances()
"""

from __future__ import annotations

from .backends.api_key import ApiKeyBackend
from .backends.base import Backend
from .backends.password import JsonFileSessionStore, PasswordBackend, SessionStore
from .client import Frigidaire
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

__all__ = [
    "Action",
    "Alert",
    "ApiKeyBackend",
    "Appliance",
    "ApplianceState",
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
    "Frigidaire",
    "FrigidaireException",
    "JsonFileSessionStore",
    "LoginError",
    "Mode",
    "PasswordBackend",
    "Power",
    "QuotaExceededError",
    "SessionCapError",
    "SessionStore",
    "Setting",
    "SleepMode",
    "Unit",
    "VerticalSwing",
]
