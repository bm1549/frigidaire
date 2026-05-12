"""Tests for the Gigya-style HMAC signature generator."""

import base64
import hashlib
import hmac
from urllib.parse import quote_plus

import pytest

from frigidaire.signature_generator import get_signature
from tests.conftest import FAKE_SESSION_SECRET as TEST_SECRET


@pytest.mark.parametrize(
    "secret,method,url,params",
    [
        ("", "POST", "https://example.com/x", {"a": "1"}),
        (TEST_SECRET, "", "https://example.com/x", {"a": "1"}),
        (TEST_SECRET, "POST", "", {"a": "1"}),
        (TEST_SECRET, "POST", "https://example.com/x", {}),
    ],
)
def test_returns_none_when_required_arg_missing(secret: str, method: str, url: str, params: dict) -> None:
    assert get_signature(secret, method, url, params) is None


def test_signature_is_deterministic() -> None:
    """Same inputs must produce identical signatures (used for replay-protection)."""
    params = {"apiKey": "abc", "format": "json", "nonce": "12345"}
    a = get_signature(TEST_SECRET, "POST", "https://example.com/path", params)
    b = get_signature(TEST_SECRET, "POST", "https://example.com/path", params)
    assert a is not None
    assert a == b


def test_signature_matches_manual_hmac() -> None:
    """Verify against an independent HMAC computation of the documented base string."""
    params = {"apiKey": "k", "nonce": "n"}
    sig = get_signature(TEST_SECRET, "POST", "https://example.com/p", params)
    assert sig is not None

    # Reproduce the base-string format: METHOD&url-encoded(URL)&url-encoded(query)
    # Query: "apiKey=k&nonce=n"; URL-encoded with %-encoding for : and /
    expected_query = "apiKey=k&nonce=n"

    def enc(s: str) -> str:
        return quote_plus(s).replace("+", "%20").replace("*", "%2A").replace("%7E", "~")

    base = f"POST&{enc('https://example.com/p')}&{enc(expected_query)}"
    key = base64.b64decode(TEST_SECRET)
    expected = base64.urlsafe_b64encode(hmac.new(key, base.encode(), hashlib.sha1).digest()).decode()
    assert sig == expected


def test_signature_normalizes_scheme_and_host_casing() -> None:
    """The reference Gigya implementation lowercases scheme + netloc before signing."""
    params = {"k": "v"}
    a = get_signature(TEST_SECRET, "POST", "HTTPS://EXAMPLE.COM/path", params)
    b = get_signature(TEST_SECRET, "POST", "https://example.com/path", params)
    assert a == b
    assert a is not None


def test_signature_ignores_url_query_and_fragment() -> None:
    """Only params dict participates; existing URL query/fragment are stripped."""
    params = {"k": "v"}
    a = get_signature(TEST_SECRET, "POST", "https://example.com/p?ignored=1", params)
    b = get_signature(TEST_SECRET, "POST", "https://example.com/p", params)
    assert a == b


def test_method_changes_signature() -> None:
    params = {"k": "v"}
    assert get_signature(TEST_SECRET, "POST", "https://example.com/p", params) != get_signature(
        TEST_SECRET, "GET", "https://example.com/p", params
    )
