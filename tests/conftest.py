"""Shared constants and helpers for the test suite."""

import base64

import responses

from frigidaire import Appliance, Frigidaire

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


def make_authenticated_client() -> Frigidaire:
    """A Frigidaire client that skips the full auth flow by presenting a valid session_key.

    Caller must be inside @responses.activate so the test_connection() GET is intercepted.
    """
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)
    return Frigidaire(username="u", password="p", session_key="valid-key", regional_base_url=REGIONAL_URL)
