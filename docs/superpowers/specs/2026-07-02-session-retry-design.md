# Cleaner, configurable session-retry layer

## Problem
`_with_reauth` duplicates its retry block, hardcodes "retry once", and detects the
session-cap error via `"cas_3403" in traceback.format_exc()` — a whole-traceback
string scan, because `FrigidaireException` carries no structured error info.

## Design (Option 2)

### 1. Structured `FrigidaireException`
Add keyword-only `status_code: int | None = None` and `error_code: str | None = None`.
Message string unchanged; existing `raise FrigidaireException("...")` sites keep working.

### 2. `parse_response` populates them
Set `status_code` from `response.status_code`; extract `error_code` from the JSON body
when present (e.g. `cas_3403`). Only place that constructs the enriched exception.

### 3. `_is_session_cap(e)` helper
`return e.error_code == "cas_3403"`. Replaces the traceback scan; drop `import traceback`.

### 4. `_with_reauth` → single configurable loop
Two new keyword-only constructor params, defaulting to today's exact behavior:
- `session_max_retries: int = 2`
- `session_retry_backoff: float = 0.0` (opt-in)

Loop: run `fn()`; on `FrigidaireException` that is `_is_session_cap` → raise immediately
(never retry/reauth); on the final allowed attempt raise; on the attempt before the last,
`re_authenticate()` first; optional `time.sleep(backoff * (attempt+1))` between attempts.

## Behavior equivalence
At defaults (`session_max_retries=2`, `backoff=0.0`) the call sequence is identical to
today: try → retry on existing session → reauth + retry. `cas_3403` still never retried.

## Testing
- `error_code`/`status_code` populated from a mocked cas_3403 body and a plain 500.
- Existing `_with_reauth` tests (500→200 no-reauth; 500→500→200 reauths once) stay green.

## Out of scope
Transport-layer retry (`max_retries_on_429`, `Retry-After`) is untouched (Option 3).
