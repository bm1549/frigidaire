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
