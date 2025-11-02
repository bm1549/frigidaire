# SPDX-License-Identifier: MIT
from __future__ import annotations
import random
import threading
import time
from typing import Callable, Optional, Set, Union, Tuple

RL_DEFAULT_METHODS: Set[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
TimeoutType = Union[float, Tuple[float, float]]  # requests supports float or (connect, read)

class RateLimiter:
    """Thread-safe limiter that ensures at least `min_interval` seconds between calls."""
    def __init__(self, min_interval: float = 1.25, jitter: float = 0.0) -> None:
        self._min = max(0.0, float(min_interval))
        self._jitter = max(0.0, float(jitter))
        self._lock = threading.Lock()
        self._next_ok_at = 0.0  # monotonic timestamp (seconds)

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            if now < self._next_ok_at:
                time.sleep(self._next_ok_at - now)
            delay = self._min + (random.uniform(0.0, self._jitter) if self._jitter else 0.0)
            self._next_ok_at = time.monotonic() + delay

    def cool_down(self, extra_seconds: float) -> None:
        if extra_seconds <= 0:
            return
        with self._lock:
            self._next_ok_at = max(self._next_ok_at, time.monotonic() + float(extra_seconds))

def _parse_retry_after_seconds(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return float(value)  # prefer seconds
    except Exception:
        return None

def wrap_session_request(
    request_func: Callable[..., "requests.Response"],
    limiter: "RateLimiter",
    rl_methods: Set[str] = RL_DEFAULT_METHODS,
    max_retry_after: float = 60.0,
    max_retries_on_429: int = 4,
    default_timeout: Optional[TimeoutType] = 15.0,
) -> Callable[..., "requests.Response"]:
    """Wrap requests.Session.request with rate limiting, 429 handling, and default timeout."""
    import time as _time

    def _wrapped(method: str, url: str, **kwargs):
        m = (method or "").upper()
        if m in rl_methods:
            limiter.wait()

        if default_timeout is not None and "timeout" not in kwargs:
            kwargs["timeout"] = default_timeout

        retries = 0
        backoff = 1.0
        while True:
            resp = request_func(method, url, **kwargs)
            status = getattr(resp, "status_code", None)
            if status in (429, 423):
                retry_after = _parse_retry_after_seconds(getattr(resp, "headers", {}).get("Retry-After"))
                delay = min(float(max_retry_after), retry_after or backoff)
                limiter.cool_down(delay)
                if retries >= max_retries_on_429:
                    return resp
                _time.sleep(delay)
                retries += 1
                backoff = min(float(max_retry_after), backoff * 2.0)
                continue
            return resp

    return _wrapped
