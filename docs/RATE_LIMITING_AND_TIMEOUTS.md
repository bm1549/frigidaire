# Rate Limiting & Default Timeouts

The client throttles mutating requests and applies a default HTTP timeout. Both are on by default.

- **Write call smoothing:** Mutating HTTP verbs (`POST`, `PUT`, `PATCH`, `DELETE`) are spaced out to avoid server lockouts (`cas_3403`).
- **Retry-After aware:** `429/423` responses back off, honoring `Retry-After` (capped).
- **Default HTTP timeout:** Per-request timeout defaults to `15s`.

## Quickstart

```python
from frigidaire import Frigidaire

api = Frigidaire("username", "password")
devices = api.get_appliances()
print(devices)
```

## Customization

All tunables are optional kwargs on `Frigidaire(...)`:

- `timeout`: per-request HTTP timeout in seconds; default `15.0`
- `rate_limit_min_interval`: seconds between write requests; default `1.25`
- `rate_limit_jitter`: random jitter added to spacing; default `0.25`
- `rate_limit_methods`: set of verbs to limit; default `{"POST","PUT","PATCH","DELETE"}`
- `rate_limit_scope_key`: share a limiter across instances by key (default: the account username)
- `max_retry_after`: cap for honoring server `Retry-After`; default `60.0`
- `max_retries_on_429`: max retries for `429/423`; default `4`

**Example:**

```python
api = Frigidaire(
    "username", "password",
    timeout=20.0,
    rate_limit_min_interval=1.5,
    rate_limit_jitter=0.3,
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

## Notes

- The rate limiter is **in-process** and keyed by `rate_limit_scope_key` (defaults to the account username).
- Reads (`GET`) are not rate-limited by default.
- The default timeout applies to every request unless a per-call `timeout=` is supplied.
