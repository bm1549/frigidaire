"""JSON-file session persistence."""

from pathlib import Path

import responses

from frigidaire import Frigidaire, JsonFileSessionStore
from tests.conftest import NO_RATE_LIMIT, REGIONAL_URL, USERS_CURRENT_URL
from tests.test_authenticate import _stub_full_auth


def test_missing_file_loads_nothing(tmp_path: Path) -> None:
    store = JsonFileSessionStore(str(tmp_path / "frigidaire.json"))
    assert store.load() == (None, None)


def test_empty_file_loads_nothing(tmp_path: Path) -> None:
    path = tmp_path / "frigidaire.json"
    path.write_text("")
    assert JsonFileSessionStore(str(path)).load() == (None, None)


def test_round_trip(tmp_path: Path) -> None:
    store = JsonFileSessionStore(str(tmp_path / "frigidaire.json"))
    store.save("key-1", REGIONAL_URL)
    assert store.load() == ("key-1", REGIONAL_URL)


@responses.activate
def test_client_loads_session_from_store(tmp_path: Path) -> None:
    store = JsonFileSessionStore(str(tmp_path / "s.json"))
    store.save("STORED-KEY", REGIONAL_URL)
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)

    client = Frigidaire(username="u", password="p", session_store=store, **NO_RATE_LIMIT)

    assert client.session_key == "STORED-KEY"
    assert len(responses.calls) == 1


@responses.activate
def test_explicit_session_key_overrides_store(tmp_path: Path) -> None:
    store = JsonFileSessionStore(str(tmp_path / "s.json"))
    store.save("STORED-KEY", REGIONAL_URL)
    responses.add(responses.GET, USERS_CURRENT_URL, json={"id": "x"}, status=200)

    client = Frigidaire(
        username="u",
        password="p",
        session_key="EXPLICIT",
        regional_base_url=REGIONAL_URL,
        session_store=store,
        **NO_RATE_LIMIT,
    )

    assert client.session_key == "EXPLICIT"
    # The store always ends up holding the key the client is using.
    assert store.load() == ("EXPLICIT", REGIONAL_URL)


@responses.activate
def test_minted_session_is_saved_to_store(tmp_path: Path) -> None:
    _stub_full_auth()
    store = JsonFileSessionStore(str(tmp_path / "s.json"))

    Frigidaire(username="u", password="p", session_store=store, **NO_RATE_LIMIT)

    assert store.load() == ("FINAL-ACCESS-TOKEN", REGIONAL_URL)


@responses.activate
def test_failing_store_does_not_break_auth(tmp_path: Path) -> None:
    _stub_full_auth()

    class Broken:
        def load(self):
            return None, None

        def save(self, session_key, regional_base_url):
            raise RuntimeError("disk full")

    client = Frigidaire(username="u", password="p", session_store=Broken(), **NO_RATE_LIMIT)
    assert client.session_key == "FINAL-ACCESS-TOKEN"
