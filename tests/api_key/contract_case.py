"""The API key backend's case for the shared backend contract tests."""

from __future__ import annotations

from tests.api_key.helpers import STREAM_EVENT, SdkMock, make_backend
from tests.contract import RECORDS, Case, CaseFactory


def _api_key() -> Case:
    sdk = SdkMock().start()
    sdk.serve(RECORDS)
    sdk.stream(STREAM_EVENT)  # the stream counts as connected once it delivers data
    backend = make_backend()
    backend.stream_initial_backoff = 60
    return Case(backend, lambda: list(sdk.sent), sdk.stop)


CASES: dict[str, CaseFactory] = {"api_key": _api_key}
