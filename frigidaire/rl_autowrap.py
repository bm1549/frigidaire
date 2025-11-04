# SPDX-License-Identifier: MIT
from __future__ import annotations

from typing import Any, Optional, Tuple, Union, Set
from .rate_limit import RateLimiter, RL_DEFAULT_METHODS, wrap_session_request

TimeoutType = Union[float, Tuple[float, float]]
_ENABLED = False

def _coerce_timeout(val: Any) -> Optional[TimeoutType]:
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, (tuple, list)) and len(val) == 2:
        return (float(val[0]), float(val[1]))
    if isinstance(val, str):
        s = val.strip()
        if "," in s:
            a, b = s.split(",", 1)
            return (float(a), float(b))
        try:
            return float(s)
        except ValueError:
            return None
    return None

def enable_autowrap() -> None:
    global _ENABLED
    if _ENABLED:
        return
    try:
        import frigidaire as pkg
    except Exception:
        return

    Frigidaire = getattr(pkg, "Frigidaire", None)
    if Frigidaire is None or getattr(Frigidaire, "_rl_patched", False):
        _ENABLED = True
        return

    orig_init = Frigidaire.__init__

    def __init__(self, username: str, password: str, *args: Any, **kwargs: Any):
        _rl_min = float(kwargs.pop("rate_limit_min_interval", 1.25))
        _rl_jit = float(kwargs.pop("rate_limit_jitter", 0.25))
        _rl_methods: Set[str] = kwargs.pop("rate_limit_methods", None) or RL_DEFAULT_METHODS
        _rl_scope = kwargs.pop("rate_limit_scope_key", None) or username
        _max_retry_after = float(kwargs.pop("max_retry_after", 60.0))
        _max_retries_on_429 = int(kwargs.pop("max_retries_on_429", 4))

        _http_timeout_raw = kwargs.pop("http_timeout", 15.0)
        _http_timeout = _coerce_timeout(_http_timeout_raw)
        if _http_timeout is None:
            _http_timeout = 15.0

        orig_init(self, username, password, *args, **kwargs)

        global _SCOPED_LIMITERS
        try:
            _SCOPED_LIMITERS  # type: ignore[name-defined]
        except NameError:
            _SCOPED_LIMITERS = {}  # type: ignore[assignment]
        limiter = _SCOPED_LIMITERS.setdefault(_rl_scope, RateLimiter(_rl_min, _rl_jit))

        try:
            self._session.request = wrap_session_request(  # type: ignore[attr-defined]
                self._session.request,  # type: ignore[attr-defined]
                limiter,
                _rl_methods,
                _max_retry_after,
                _max_retries_on_429,
                default_timeout=_http_timeout,
            )
        except Exception:
            pass

    Frigidaire.__init__ = __init__  # type: ignore[method-assign]
    Frigidaire._rl_patched = True  # type: ignore[attr-defined]
    _ENABLED = True
