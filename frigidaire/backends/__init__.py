"""Backends: the ways the library reaches an account's appliances.

Each backend implements :class:`~frigidaire.backends.base.Backend`. Shared code depends only on
that protocol, never on a particular backend, so a backend package can be deleted without
touching anything else.
"""

from __future__ import annotations

from .base import Backend, ConnectionCallback, RecordCallback

__all__ = ["Backend", "ConnectionCallback", "RecordCallback"]
