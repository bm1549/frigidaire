"""Regression: credentials must not appear in error logs or exceptions.

Issue #41 in this repo had a user paste their full bearer token into a public
GitHub issue because handle_request_exception logged unredacted headers.
Auth-flow payloads also contain plaintext passwords and tokens.
"""

import json
import logging

import pytest

from frigidaire import Frigidaire, FrigidaireException, _redact_headers, _redact_payload

FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.test-payload.test-signature"
FAKE_API_KEY = "test-api-key-do-not-leak"
FAKE_PASSWORD = "test-password-do-not-leak"


def test_redact_headers_masks_credentials() -> None:
    redacted = _redact_headers(
        {"Authorization": f"Bearer {FAKE_JWT}", "x-api-key": FAKE_API_KEY, "Accept": "application/json"}
    )
    assert FAKE_JWT not in str(redacted)
    assert FAKE_API_KEY not in str(redacted)
    assert redacted["Accept"] == "application/json"


def test_redact_headers_is_case_insensitive() -> None:
    redacted = _redact_headers({"AUTHORIZATION": f"Bearer {FAKE_JWT}", "X-API-KEY": FAKE_API_KEY})
    assert FAKE_JWT not in str(redacted)
    assert FAKE_API_KEY not in str(redacted)


def test_redact_payload_masks_known_sensitive_keys() -> None:
    payload = json.dumps(
        {
            "loginID": "user@example.com",
            "password": FAKE_PASSWORD,
            "clientSecret": "secret-do-not-leak",
            "idToken": FAKE_JWT,
            "apiKey": FAKE_API_KEY,
            "sig": "hmac-sig-do-not-leak",
            "format": "json",
        }
    )
    redacted = _redact_payload(payload)
    assert FAKE_PASSWORD not in redacted
    assert "secret-do-not-leak" not in redacted
    assert FAKE_JWT not in redacted
    assert FAKE_API_KEY not in redacted
    assert "hmac-sig-do-not-leak" not in redacted
    # Non-sensitive fields preserved
    assert "user@example.com" in redacted
    assert "json" in redacted


def test_redact_payload_passes_through_non_json() -> None:
    """Form-encoded or malformed bodies are returned untouched (better to log
    raw than to crash the error path)."""
    assert _redact_payload("") == ""
    assert _redact_payload("not-json-at-all") == "not-json-at-all"
    # JSON arrays and primitives are passed through (no top-level keys to redact)
    assert _redact_payload("[1, 2, 3]") == "[1, 2, 3]"


def test_handle_request_exception_redacts_in_message_and_log(caplog: pytest.LogCaptureFixture) -> None:
    headers = {
        "Authorization": f"Bearer {FAKE_JWT}",
        "x-api-key": FAKE_API_KEY,
        "User-Agent": "Ktor client",
    }
    payload = json.dumps({"loginID": "user@example.com", "password": FAKE_PASSWORD})
    caplog.set_level(logging.WARNING)
    with pytest.raises(FrigidaireException) as exc_info:
        Frigidaire.handle_request_exception(RuntimeError("boom"), "POST", "https://example.com/login", headers, payload)

    leaked = (FAKE_JWT, FAKE_API_KEY, FAKE_PASSWORD)
    for secret in leaked:
        assert secret not in str(exc_info.value), f"{secret!r} leaked into raised exception"
        assert secret not in caplog.text, f"{secret!r} leaked into warning log"
    # Sanity: non-sensitive context still present
    assert "Ktor client" in str(exc_info.value)
    assert "user@example.com" in str(exc_info.value)


def test_handle_request_exception_does_not_log_inner_exception_unredacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Inner FrigidaireExceptions from parse_response carry the response body,
    which for auth endpoints can contain tokens."""
    inner = FrigidaireException(f'Request failed with status 200: b\'{{"id_token": "{FAKE_JWT}"}}\'')
    caplog.set_level(logging.WARNING)
    with pytest.raises(FrigidaireException):
        Frigidaire.handle_request_exception(inner, "POST", "https://example.com/jwt", {}, "")
    assert FAKE_JWT not in caplog.text, "inner exception leaked a token into the warning log"
