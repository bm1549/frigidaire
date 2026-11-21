"""The 1.x import path of :mod:`frigidaire.backends.password.signature_generator`, kept through 1.x.

This name resolves to that module itself, so reading or patching anything through the old path,
private names included, reaches the real module.
"""

from __future__ import annotations

import sys

from .backends.password import signature_generator as _module
from .backends.password.signature_generator import (
    get_signature as get_signature,
)

sys.modules[__name__] = _module
