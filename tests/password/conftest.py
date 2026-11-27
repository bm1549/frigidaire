"""Fixtures for the password backend's tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
import responses

from tests.password.helpers import reset_scoped_state


@pytest.fixture(autouse=True)
def _reset_scoped_state() -> None:
    """Each test gets a fresh limiter and re-auth lock scope so neither leaks across tests."""
    reset_scoped_state()


@pytest.fixture
def http_mock() -> Iterator[None]:
    """Activate ``responses``' default mock for async tests, where ``@responses.activate`` does not fit.

    The mock patches ``requests`` process-wide, so it also covers calls the password backend makes
    from worker threads.
    """
    responses.start()
    try:
        yield
    finally:
        responses.stop()
        responses.reset()
