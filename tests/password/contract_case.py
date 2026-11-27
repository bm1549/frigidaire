"""The password backend's case for the shared backend contract tests."""

from __future__ import annotations

import json

import responses

from frigidaire import PasswordBackend
from tests.contract import IDS, RECORDS, Case, CaseFactory
from tests.password.helpers import (
    APPLIANCES_URL,
    COMMAND_URL,
    NO_RATE_LIMIT,
    REGIONAL_URL,
    USERS_CURRENT_URL,
    reset_scoped_state,
)


def _password() -> Case:
    reset_scoped_state()
    # The default mock patches requests process-wide, so it also covers the worker threads.
    responses.start()
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)
    responses.add(responses.GET, APPLIANCES_URL, json=RECORDS, status=200)
    for appliance_id in IDS:
        responses.add(responses.PUT, COMMAND_URL.format(appliance_id), json={}, status=200)
    backend = PasswordBackend(
        "user@example.com",
        "secret",
        session_key="valid-key",
        regional_base_url=REGIONAL_URL,
        **NO_RATE_LIMIT,  # type: ignore[arg-type]
    )

    def sent() -> list[tuple[str, str, object]]:
        result = []
        for call in responses.calls:
            if call.request.method == "PUT":
                appliance_id = call.request.url.split("/appliances/")[1].split("/")[0]
                ((key, value),) = json.loads(call.request.body).items()
                result.append((appliance_id, key, value))
        return result

    def cleanup() -> None:
        responses.stop()
        responses.reset()
        reset_scoped_state()

    return Case(backend, sent, cleanup)


CASES: dict[str, CaseFactory] = {"password": _password}
