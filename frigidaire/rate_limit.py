"""The 1.x import path of :mod:`frigidaire.backends.password.rate_limit`, kept through 1.x.

This name resolves to that module itself, so reading or patching anything through the old path,
private names included, reaches the real module.
"""

from __future__ import annotations

import sys

from .backends.password import rate_limit as _module
from .backends.password.rate_limit import (
    RateLimiter as RateLimiter,
    wrap_session_request as wrap_session_request,
)

sys.modules[__name__] = _module
