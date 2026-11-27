"""The 1.0 import paths and module names still reach the moved password code."""

from __future__ import annotations

import importlib
import logging
import time

import pytest

import frigidaire
from frigidaire.backends.password import rate_limit, session_store, signature_generator, transport


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("frigidaire.rate_limit", rate_limit),
        ("frigidaire.session_store", session_store),
        ("frigidaire.signature_generator", signature_generator),
    ],
)
def test_alias_modules_are_the_moved_modules(old: str, new: object) -> None:
    assert importlib.import_module(old) is new
    assert getattr(frigidaire, old.split(".")[1]) is new


def test_old_from_imports_work() -> None:
    from frigidaire.rate_limit import RateLimiter, _parse_retry_after_seconds, wrap_session_request
    from frigidaire.session_store import JsonFileSessionStore, SessionStore
    from frigidaire.signature_generator import get_signature

    assert RateLimiter is rate_limit.RateLimiter
    assert wrap_session_request is rate_limit.wrap_session_request
    assert _parse_retry_after_seconds is rate_limit._parse_retry_after_seconds
    assert JsonFileSessionStore is session_store.JsonFileSessionStore is frigidaire.JsonFileSessionStore
    assert SessionStore is session_store.SessionStore
    assert get_signature is signature_generator.get_signature


def test_patching_through_the_old_path_reaches_the_real_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("frigidaire.rate_limit._parse_retry_after_seconds", lambda value: 42.0)
    assert rate_limit._parse_retry_after_seconds("1") == 42.0


def test_moved_modules_keep_their_logger_names() -> None:
    assert rate_limit._LOGGER is logging.getLogger("frigidaire.rate_limit")
    assert session_store._LOGGER is logging.getLogger("frigidaire.session_store")


def test_old_module_level_names_are_the_transport_ones() -> None:
    assert frigidaire._SCOPED_LIMITERS is transport._SCOPED_LIMITERS
    assert frigidaire._SCOPED_REAUTH_LOCKS is transport._SCOPED_REAUTH_LOCKS
    assert frigidaire._redact_headers is transport._redact_headers
    assert frigidaire._redact_payload is transport._redact_payload
    assert frigidaire.GLOBAL_API_URL == transport.GLOBAL_API_URL
    assert frigidaire.time is time
