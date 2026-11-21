# Working in this repo

Consumed only by bm1549/home-assistant-frigidaire. This library owns everything about the appliances; keep Home Assistant concepts out of it.

## Setup and checks

```
uv venv .venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q && .venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy frigidaire
```

Python 3.10 compatible: no `match`, no `StrEnum`, `from __future__ import annotations` everywhere.

## Layout

- `model.py`: wire vocabulary as `CaseInsensitiveEnum`s (firmware reports `RUNNING` or `running`), `Detail` keys, `Appliance` snapshot accessors, `Action` builders. Shared by every backend.
- `client.py`: the async `Frigidaire` facade over one backend: `connect`, `get_appliances`, `refresh`, `listen`, and the `set_*` commands that encode ordering quirks (power-on first, setpoint last, Dry before a humidity target, AC "auto" is ECO), one property per `send`.
- `backends/base.py`: the `Backend` protocol and the internal record format every backend returns.
- `backends/password/`: the email-and-password backend, deletable as a unit. `PasswordBackend` runs the blocking `PasswordTransport` (Gigya login, HTTP, redaction, re-auth lock, write throttling in `rate_limit.py`) on a worker thread; `session_store.py` holds `JsonFileSessionStore` (the store always holds the session in use).
- `backends/api_key/`: `ApiKeyBackend` on the official Electrolux SDK, the only module that imports it, deletable as a unit. Token refresh with a lock and rotated pairs to `on_tokens`, the event stream behind `listen`, SDK log redaction; `records.py` builds internal records from the SDK's list, info and state calls.
- `exceptions.py`: `LoginError` > `AuthenticationError` (rejected credentials: Gigya 403042/403041, or for the API key an HTTP 401/403 or a refresh the token endpoint rejected), `SessionCapError` (cas_3403, password only), `QuotaExceededError` (429 with `retry_after`), `CommandRejectedError` (406).
- `__init__.py`: public exports only; the one shared module that imports the backends.
- `testing.py`: `FakeBackend` (canned records, records what it sends, drives `listen` with `push`/`reconnect`), `FakeFrigidaire`, and real sample records. The HA repo's tests depend on it.
- Shared code never imports `backends/password` or `backends/api_key`. Their tests live in `tests/password/` and `tests/api_key/`, each with its own helpers, conftest and `contract_case.py`, which `tests/test_backend_contract.py` finds by name; deleting a backend means deleting its package, its test package and its exports.

## Rules

- Accessors return `None` when a model does not report a value. Never raise on an unknown wire value; add it to the enum and a test.
- New reported key: add to `Detail`, add an accessor, cover it with a sample from a real payload (issues #25, #43; HA issues #49, #87, #121).
- Never log in again in response to `SessionCapError`. Never log auth response bodies, tokens or API keys; the API key backend also keeps SDK response bodies and exception text out of logs.
- Every push to main publishes to PyPI with a patch bump and opens a bump PR in the HA repo. Breaking changes need a manual tag for a larger bump.
- Commit messages: one subject line, no body, no trailers.
