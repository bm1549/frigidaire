"""Constants and helpers for the password backend's tests. Only tests under ``tests/password`` use them."""

from __future__ import annotations

import base64

import responses

from frigidaire.backends.password.transport import _SCOPED_LIMITERS, _SCOPED_REAUTH_LOCKS, PasswordTransport

# Default kwargs that disable rate limiting and 429 retries — tests should
# spread these into PasswordTransport() and PasswordBackend() constructors so they run instantly.
NO_RATE_LIMIT: dict[str, object] = {
    "rate_limit_min_interval": 0.0,
    "rate_limit_jitter": 0.0,
    "max_retries_on_429": 0,
}

GLOBAL_URL = "https://api.ocp.electrolux.one"
REGIONAL_URL = "https://api.us.ocp.electrolux.one"
IDENTITY_DOMAIN = "us1-id.gigya.com"

USERS_CURRENT_URL = f"{REGIONAL_URL}/one-account-user/api/v1/users/current?countryDetails=true"
APPLIANCES_URL = f"{REGIONAL_URL}/appliance/api/v2/appliances?includeMetadata=true"
COMMAND_URL = f"{REGIONAL_URL}/appliance/api/v2/appliances/{{}}/command"

# A throwaway base64 secret so accounts.getJWT signature generation succeeds in tests.
FAKE_SESSION_SECRET = base64.b64encode(b"\x00" * 16).decode()


def reset_scoped_state() -> None:
    """Forget every account's rate limiter and re-auth lock, so neither leaks across tests."""
    _SCOPED_LIMITERS.clear()
    _SCOPED_REAUTH_LOCKS.clear()


def make_authenticated_client(**overrides: object) -> PasswordTransport:
    """A password transport that skips the full auth flow by presenting a valid session_key.

    Rate limiting and 429 retries are disabled by default to keep tests fast and deterministic;
    callers exercising those features can pass them via overrides.

    Caller must be inside @responses.activate so the test_connection() GET is intercepted.
    """
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)
    kwargs: dict[str, object] = {
        "username": "u",
        "password": "p",
        "session_key": "valid-key",
        "regional_base_url": REGIONAL_URL,
        **NO_RATE_LIMIT,
        **overrides,
    }
    return PasswordTransport(**kwargs)  # type: ignore[arg-type]
