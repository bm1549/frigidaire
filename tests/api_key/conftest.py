"""Fixtures for the API key backend's tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from tests.api_key.helpers import SdkMock


@pytest.fixture
def sdk() -> Iterator[SdkMock]:
    sdk_mock = SdkMock().start()
    try:
        yield sdk_mock
    finally:
        sdk_mock.stop()
