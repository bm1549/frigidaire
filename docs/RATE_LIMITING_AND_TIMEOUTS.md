# Rate Limiting & Default Timeouts (Backwards-Compatible)

This fork adds a **client-side write rate limiter** and **default HTTP timeouts** without breaking existing callers.

- **Backwards compatible:** Existing code that calls `Frigidaire(email, password)` keeps working.
- **Write call smoothing:** Mutating HTTP verbs (`POST`, `PUT`, `PATCH`, `DELETE`) are spaced out by default to avoid server lockouts.
- **Retry-After aware:** `429/423` responses back off, honoring `Retry-After` (capped).
- **Default HTTP timeout:** If a request doesn’t pass `timeout=...`, a library default is applied (`15s` by default).

## Quickstart

```python
from frigidaire import Frigidaire
# If your build doesn't auto-enable autowrap at import time, uncomment one of these:
# import frigidaire.rl_autowrap as _
# from frigidaire.rl_autowrap import enable_autowrap; enable_autowrap()

api = Frigidaire("email", "password")
devices = api.get_appliances()
print(devices)
```

## Customization (optional)

You can pass kwargs to `Frigidaire(...)` to tune behavior. All are optional:

- `http_timeout`: float or `(connect, read)` tuple; default `15.0` seconds
- `rate_limit_min_interval`: seconds between write requests; default `1.25`
- `rate_limit_jitter`: random jitter added to spacing; default `0.25`
- `rate_limit_methods`: set of verbs to limit; default `{"POST","PUT","PATCH","DELETE"}`
- `rate_limit_scope_key`: share a limiter across instances by key (default: the account email)
- `max_retry_after`: cap for honoring server `Retry-After`; default `60.0`
- `max_retries_on_429`: max retries for `429/423`; default `4`

**Example:**

```python
api = Frigidaire(
    "email", "password",
    http_timeout=20.0,                # or (5, 30)
    rate_limit_min_interval=1.5,      # seconds between writes
    rate_limit_jitter=0.3,            # smooth bursts
    max_retry_after=90.0,
    max_retries_on_429=5,
    # rate_limit_methods={"POST","PUT","PATCH","DELETE"},
    # rate_limit_scope_key="household-42",
)
```

## CLI Smoke Tests

We provide a small script in `scripts/smoke_test_frigidaire.py` that exercises the new features without changing device state.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

export FRIGIDAIRE_EMAIL="you@example.com"
export FRIGIDAIRE_PASSWORD="••••••••"

# Optional tunables for the test run
export MIN_INTERVAL=1.5
export JITTER=0.0
export HTTP_TIMEOUT=15.0

python scripts/smoke_test_frigidaire.py       --min-interval "${MIN_INTERVAL:-1.5}"       --jitter "${JITTER:-0.0}"       --http-timeout "${HTTP_TIMEOUT:-15.0}"
```

What it checks:

1. **Auth + list devices** (read-only)
2. **Default timeout** (~15s) using a delayed URL when no per-request timeout is passed
3. **Rate-limit spacing** using harmless POSTs to prove gaps between writes
4. **Retry-After** handling — tries a live 429, then falls back to a local simulation if the live check is blocked

## Opt-in vs. auto-enable

If your package enables autowrap at import time (via a small block in `frigidaire/__init__.py`), no changes are needed by callers.  
Otherwise, add one of these once at startup:

```python
import frigidaire.rl_autowrap as _
# or
from frigidaire.rl_autowrap import enable_autowrap
enable_autowrap()
```

## Notes

- The rate limiter is **in-process** and keyed by `rate_limit_scope_key` (defaults to the account email).
- Reads (`GET`) are not rate-limited by default.
- Timeouts apply **only** when a given request doesn’t already supply `timeout=`.
- For Home Assistant users, no changes are required if the library is imported normally and autowrap is enabled.
