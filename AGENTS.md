# Working in this repo

Consumed only by bm1549/home-assistant-frigidaire. This library owns everything about the appliances; keep Home Assistant concepts out of it.

## Setup and checks

```
uv venv .venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q && .venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy frigidaire
```

Python 3.10 compatible: no `match`, no `StrEnum`, `from __future__ import annotations` everywhere.

## Layout

- `model.py`: wire vocabulary as `CaseInsensitiveEnum`s (firmware reports `RUNNING` or `running`), `Detail` keys, `Appliance` snapshot accessors, `Action` builders.
- `__init__.py`: auth, HTTP, `get_appliances()`, and the `set_*` commands that encode ordering quirks (power-on first, setpoint last, Dry before a humidity target, AC "auto" is ECO).
- `exceptions.py`: `LoginError` > `AuthenticationError` (Gigya 403042/403041 only), `SessionCapError` (cas_3403).
- `session_store.py`: `JsonFileSessionStore`; the store always holds the session in use.
- `testing.py`: `FakeFrigidaire` replaces the transport only, plus real sample records. The HA repo's tests depend on it.

## Rules

- Accessors return `None` when a model does not report a value. Never raise on an unknown wire value; add it to the enum and a test.
- New reported key: add to `Detail`, add an accessor, cover it with a sample from a real payload (issues #25, #43; HA issues #49, #87, #121).
- Never log in again in response to `SessionCapError`. Never log auth response bodies.
- Every push to main publishes to PyPI with a patch bump and opens a bump PR in the HA repo. Breaking changes need a manual tag for a larger bump.
- Commit messages: one subject line, no body, no trailers.
