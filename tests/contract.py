"""What a backend's contract case provides; see ``tests/test_backend_contract.py``.

Each backend's test package has a ``contract_case`` module whose ``CASES`` maps a case name to a
factory returning a :class:`Case`. The contract test finds those modules itself, so deleting a
backend's test package removes its case without touching shared files.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from frigidaire import Backend
from frigidaire.testing import DEHUMIDIFIER, LEGACY_AC

RECORDS = [LEGACY_AC, DEHUMIDIFIER]
"""The two appliances every case serves, with the same ``properties.reported``."""
IDS = [r["applianceId"] for r in RECORDS]


@dataclass
class Case:
    backend: Backend
    sent: Callable[[], list[tuple[str, str, object]]]
    """Every (appliance_id, key, value) the backend has sent, in order."""
    cleanup: Callable[[], None] = field(default=lambda: None)
    """Undo whatever mocking the factory started."""


CaseFactory = Callable[[], Case]
