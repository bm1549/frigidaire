"""The 1.x import path of :mod:`frigidaire.backends.password.session_store`, kept through 1.x.

This name resolves to that module itself, so reading or patching anything through the old path,
private names included, reaches the real module.
"""

from __future__ import annotations

import sys

from .backends.password import session_store as _module
from .backends.password.session_store import (
    JsonFileSessionStore as JsonFileSessionStore,
    SessionStore as SessionStore,
)

sys.modules[__name__] = _module
