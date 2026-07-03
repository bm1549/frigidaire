"""Tests for Frigidaire.parse_response branches."""

import gzip
import json
from unittest.mock import MagicMock

import pytest

from frigidaire import Frigidaire, FrigidaireException


def _resp(status: int, content: bytes, headers: dict | None = None, json_data: object = None) -> MagicMock:
    r = MagicMock(status_code=status, content=content, headers=headers or {})
    r.json.return_value = json_data
    return r


def test_non_200_raises_frigidaire_exception() -> None:
    r = _resp(500, b'{"error":"x"}', json_data={"error": "x"})
    with pytest.raises(FrigidaireException, match="status 500"):
        Frigidaire.parse_response(r)


def test_plain_json_body() -> None:
    body = {"hello": "world"}
    r = _resp(200, json.dumps(body).encode(), json_data=body)
    assert Frigidaire.parse_response(r) == body


def test_empty_body_returns_empty_dict() -> None:
    """API sometimes claims JSON but sends an empty body — treat as {}."""
    r = _resp(200, b"", headers={"Content-Type": "application/json"})
    assert Frigidaire.parse_response(r) == {}


def test_actual_gzip_body() -> None:
    body = {"hello": "gzipped"}
    raw = gzip.compress(json.dumps(body).encode())
    r = _resp(200, raw, headers={"Content-Encoding": "gzip"})
    assert Frigidaire.parse_response(r) == body


def test_gzip_header_but_plain_body_falls_back_to_json() -> None:
    """Server lies about Content-Encoding: gzip but sends plain JSON."""
    body = {"hello": "not_actually_gzipped"}
    r = _resp(200, json.dumps(body).encode(), headers={"Content-Encoding": "gzip"}, json_data=body)
    assert Frigidaire.parse_response(r) == body


def test_invalid_json_body_raises() -> None:
    r = MagicMock(status_code=200, content=b"not json at all", headers={})
    r.json.side_effect = ValueError("invalid")
    with pytest.raises(FrigidaireException, match="unexpected response"):
        Frigidaire.parse_response(r)


def test_error_response_carries_structured_status_and_code() -> None:
    """The session-cap error must be identifiable without scanning the traceback string."""
    r = _resp(429, b'{"error":"cas_3403"}', json_data={"error": "cas_3403"})
    with pytest.raises(FrigidaireException) as exc_info:
        Frigidaire.parse_response(r)
    assert exc_info.value.status_code == 429
    assert exc_info.value.error_code == "cas_3403"


def test_error_response_without_error_field_has_none_code() -> None:
    r = _resp(500, b'{"detail":"boom"}', json_data={"detail": "boom"})
    with pytest.raises(FrigidaireException) as exc_info:
        Frigidaire.parse_response(r)
    assert exc_info.value.status_code == 500
    assert exc_info.value.error_code is None


def test_error_response_with_unparseable_body_still_sets_status() -> None:
    r = MagicMock(status_code=503, content=b"<html>gateway</html>", headers={})
    r.json.side_effect = ValueError("invalid")
    with pytest.raises(FrigidaireException) as exc_info:
        Frigidaire.parse_response(r)
    assert exc_info.value.status_code == 503
    assert exc_info.value.error_code is None


def test_handle_request_exception_propagates_structured_fields() -> None:
    """The outer exception raised by request wrappers must carry the cause's status/error code."""
    cause = FrigidaireException("orig", status_code=429, error_code="cas_3403")
    with pytest.raises(FrigidaireException) as exc_info:
        Frigidaire.handle_request_exception(cause, "GET", "http://x/y", {}, "")
    assert exc_info.value.status_code == 429
    assert exc_info.value.error_code == "cas_3403"
