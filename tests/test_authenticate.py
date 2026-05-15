"""Tests for the multi-step authenticate() flow.

The flow has 5 hops: client_credentials token, identity-providers lookup,
socialize.getIDs, accounts.login, accounts.getJWT, then token-exchange.
"""

import pytest
import responses

from frigidaire import Frigidaire, FrigidaireException
from tests.conftest import (
    FAKE_SESSION_SECRET,
    GLOBAL_URL,
    IDENTITY_DOMAIN,
    NO_RATE_LIMIT,
    REGIONAL_URL,
    USERS_CURRENT_URL,
)


def _stub_full_auth() -> None:
    """Set up the full happy-path auth chain. Caller must be inside @responses.activate."""
    # 1. client_credentials → temporary access token
    responses.add(
        responses.POST,
        f"{GLOBAL_URL}/one-account-authorization/api/v1/token",
        json={"accessToken": "temp-bootstrap-token"},
        status=200,
    )
    # 2. identity-providers lookup
    responses.add(
        responses.GET,
        f"{GLOBAL_URL}/one-account-user/api/v1/identity-providers?brand=frigidaire&countryCode=US",
        json=[{"domain": IDENTITY_DOMAIN, "apiKey": "gigya-api-key", "httpRegionalBaseUrl": REGIONAL_URL}],
        status=200,
    )
    # 3. socialize.getIDs
    responses.add(
        responses.POST,
        f"https://socialize.{IDENTITY_DOMAIN}/socialize.getIDs",
        json={"gmid": "GMID", "ucid": "UCID"},
        status=200,
    )
    # 4. accounts.login
    responses.add(
        responses.POST,
        f"https://accounts.{IDENTITY_DOMAIN}/accounts.login",
        json={"sessionInfo": {"sessionToken": "SESSION-TOK", "sessionSecret": FAKE_SESSION_SECRET}},
        status=200,
    )
    # 5. accounts.getJWT
    responses.add(
        responses.POST,
        f"https://accounts.{IDENTITY_DOMAIN}/accounts.getJWT",
        json={"id_token": "JWT-TOKEN"},
        status=200,
    )
    # 6. token exchange → final session_key
    responses.add(
        responses.POST,
        f"{REGIONAL_URL}/one-account-authorization/api/v1/token",
        json={"accessToken": "FINAL-ACCESS-TOKEN"},
        status=200,
    )


@responses.activate
def test_full_authenticate_happy_path() -> None:
    _stub_full_auth()
    client = Frigidaire(username="user", password="pass", **NO_RATE_LIMIT)
    assert client.session_key == "FINAL-ACCESS-TOKEN"
    assert client.regional_base_url == REGIONAL_URL


@responses.activate
def test_authenticate_raises_when_session_info_missing() -> None:
    """The library detects malformed login responses early."""
    _stub_full_auth()
    responses.replace(
        responses.POST,
        f"https://accounts.{IDENTITY_DOMAIN}/accounts.login",
        json={"errorMessage": "bad credentials"},  # no sessionInfo
        status=200,
    )

    with pytest.raises(FrigidaireException, match="sessionInfo was not in response"):
        Frigidaire(username="user", password="pass", **NO_RATE_LIMIT)


@responses.activate
def test_authenticate_raises_when_final_token_missing() -> None:
    _stub_full_auth()
    responses.replace(
        responses.POST,
        f"{REGIONAL_URL}/one-account-authorization/api/v1/token",
        json={"unexpected": "shape"},
        status=200,
    )

    with pytest.raises(FrigidaireException, match="accessToken was not in response"):
        Frigidaire(username="user", password="pass", **NO_RATE_LIMIT)


@responses.activate
def test_existing_session_key_validated_with_test_connection() -> None:
    """When given a session_key + regional_base_url, init verifies via /users/current only."""
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "user-id"}, status=200)
    client = Frigidaire(
        username="u", password="p", session_key="EXISTING-KEY", regional_base_url=REGIONAL_URL, **NO_RATE_LIMIT
    )
    assert client.session_key == "EXISTING-KEY"
    assert len(responses.calls) == 1  # only test_connection fired


@responses.activate
def test_invalid_existing_session_key_triggers_full_reauth() -> None:
    """If test_connection fails, init falls through to the full auth flow."""
    responses.add(responses.GET, USERS_CURRENT_URL, json={"error": "expired"}, status=401)
    _stub_full_auth()

    client = Frigidaire(
        username="u", password="p", session_key="EXPIRED", regional_base_url=REGIONAL_URL, **NO_RATE_LIMIT
    )
    assert client.session_key == "FINAL-ACCESS-TOKEN"
