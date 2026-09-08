"""Structured exceptions: callers classify failures by type, not by string matching."""

import pytest
import responses

from frigidaire import (
    AuthenticationError,
    Frigidaire,
    FrigidaireException,
    SessionCapError,
)
from tests.conftest import APPLIANCES_URL, IDENTITY_DOMAIN, NO_RATE_LIMIT, make_authenticated_client
from tests.test_authenticate import _stub_full_auth


def test_session_cap_is_a_typed_exception() -> None:
    from tests.test_parse_response import _resp

    r = _resp(429, b'{"error":"cas_3403"}', json_data={"error": "cas_3403"})
    with pytest.raises(SessionCapError) as exc_info:
        Frigidaire.parse_response(r)
    assert isinstance(exc_info.value, FrigidaireException)
    assert exc_info.value.status_code == 429


def test_handle_request_exception_preserves_subclass() -> None:
    cause = SessionCapError("orig", status_code=429, error_code="cas_3403")
    with pytest.raises(SessionCapError) as exc_info:
        Frigidaire.handle_request_exception(cause, "GET", "http://x/y", {}, "")
    assert exc_info.value.error_code == "cas_3403"


@responses.activate
def test_session_cap_propagates_typed_through_get_appliances() -> None:
    client = make_authenticated_client()
    responses.add(responses.GET, APPLIANCES_URL, json={"error": "cas_3403"}, status=429)
    with pytest.raises(SessionCapError):
        client.get_appliances()


@responses.activate
def test_rejected_login_raises_authentication_error() -> None:
    _stub_full_auth()
    responses.replace(
        responses.POST,
        f"https://accounts.{IDENTITY_DOMAIN}/accounts.login",
        json={"errorCode": 403042, "errorMessage": "Invalid LoginID"},
        status=200,
    )
    with pytest.raises(AuthenticationError):
        Frigidaire(username="user", password="wrong", **NO_RATE_LIMIT)


@responses.activate
def test_authentication_error_is_a_frigidaire_exception() -> None:
    _stub_full_auth()
    responses.replace(
        responses.POST,
        f"https://accounts.{IDENTITY_DOMAIN}/accounts.login",
        json={"errorCode": 403042},
        status=200,
    )
    with pytest.raises(FrigidaireException):
        Frigidaire(username="user", password="wrong", **NO_RATE_LIMIT)


@responses.activate
def test_session_cap_while_testing_the_session_is_not_retried_with_a_new_login() -> None:
    """Minting a new session in response to the cap is what makes the cap worse."""
    from tests.conftest import REGIONAL_URL, USERS_CURRENT_URL

    responses.add(responses.GET, USERS_CURRENT_URL, json={"error": "cas_3403"}, status=429)
    _stub_full_auth()
    with pytest.raises(SessionCapError):
        Frigidaire(username="u", password="p", session_key="k", regional_base_url=REGIONAL_URL, **NO_RATE_LIMIT)
    assert [c.request.url for c in responses.calls] == [USERS_CURRENT_URL]
