"""Shared constants and helpers for the test suite."""

import base64

import pytest
import responses

from frigidaire import _SCOPED_LIMITERS, Appliance, Frigidaire

# Default kwargs that disable rate limiting and 429 retries — tests should
# spread these into Frigidaire() constructors so they run instantly.
NO_RATE_LIMIT: dict[str, object] = {
    "rate_limit_min_interval": 0.0,
    "rate_limit_jitter": 0.0,
    "max_retries_on_429": 0,
}


@pytest.fixture(autouse=True)
def _reset_scoped_limiters() -> None:
    """Each test gets a fresh limiter scope so spacing doesn't leak across tests."""
    _SCOPED_LIMITERS.clear()

GLOBAL_URL = "https://api.ocp.electrolux.one"
REGIONAL_URL = "https://api.us.ocp.electrolux.one"
IDENTITY_DOMAIN = "us1-id.gigya.com"

USERS_CURRENT_URL = f"{REGIONAL_URL}/one-account-user/api/v1/users/current?countryDetails=true"
APPLIANCES_URL = f"{REGIONAL_URL}/appliance/api/v2/appliances?includeMetadata=true"

# A throwaway base64 secret so accounts.getJWT signature generation succeeds in tests.
FAKE_SESSION_SECRET = base64.b64encode(b"\x00" * 16).decode()


def make_raw_appliance(
    model_name: str = "AC",
    reported: dict | None = None,
    nickname: str = "Living Room",
    appliance_id: str = "FAKE-ID-123",
) -> dict:
    """Build the raw applianceData shape returned by /appliance/api/v2/appliances."""
    return {
        "applianceId": appliance_id,
        "applianceData": {"modelName": model_name, "applianceName": nickname},
        "properties": {"reported": reported or {}},
    }


def make_appliance(model_name: str = "AC", appliance_id: str = "AC1", nickname: str = "x") -> Appliance:
    """Build a constructed Appliance (no reported properties)."""
    return Appliance(make_raw_appliance(model_name=model_name, appliance_id=appliance_id, nickname=nickname))


def make_authenticated_client(**overrides: object) -> Frigidaire:
    """A Frigidaire client that skips the full auth flow by presenting a valid session_key.

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
    }
    kwargs.update(overrides)
    return Frigidaire(**kwargs)  # type: ignore[arg-type]
