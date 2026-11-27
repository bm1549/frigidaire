# Frigidaire Python API

A Python client for the Frigidaire 2.0 (Electrolux) cloud API, reverse-engineered from the mobile
app. It drives Frigidaire Wi-Fi air conditioners and dehumidifiers, and is the library behind the
[Home Assistant Frigidaire integration](https://github.com/bm1549/home-assistant-frigidaire).

There are two clients with the same commands and the same appliance snapshots:

- `Frigidaire(username, password, ...)`, the synchronous client. It is unchanged from 1.0, so
  existing code keeps working as it is.
- `AsyncFrigidaire(backend)`, the async client, new in 1.1. It is built from a backend, the way
  the account signs in; `PasswordBackend` signs in with the email and password of the Frigidaire
  app. New code, and anything running on an event loop, should use it.

## Quickstart: the sync client

```python
from frigidaire import Frigidaire, JsonFileSessionStore, Mode

client = Frigidaire("email", "password", session_store=JsonFileSessionStore("session.json"))

for appliance in client.get_appliances():
    print(appliance, appliance.state, appliance.mode, appliance.ambient_temperature, appliance.temperature_unit)

ac = client.get_appliances()[0]
client.set_mode(ac, Mode.COOL)
client.set_temperature(ac, 72)
```

The constructor signs in, and every call blocks while it makes its HTTP requests.

## Quickstart: the async client

```python
import asyncio

from frigidaire import AsyncFrigidaire, JsonFileSessionStore, Mode, PasswordBackend


async def main() -> None:
    backend = PasswordBackend("email", "password", session_store=JsonFileSessionStore("session.json"))
    client = AsyncFrigidaire(backend)
    await client.connect()

    for appliance in await client.get_appliances():
        print(appliance, appliance.state, appliance.mode, appliance.ambient_temperature, appliance.temperature_unit)

    ac = (await client.get_appliances())[0]
    await client.set_mode(ac, Mode.COOL)
    await client.set_temperature(ac, 72)
    ac = await client.refresh(ac)

    await client.close()


asyncio.run(main())
```

`PasswordBackend` takes the same arguments as the sync client. It runs the same blocking HTTP code
on a worker thread, so it never stalls the event loop, and it shares each account's write
throttle and re-authentication lock with any sync client in the same process. It has no live
updates: poll `get_appliances()`, or `refresh(appliance)` for one appliance. `client.listen()`
raises `NotImplementedError` on it.

## Appliances and commands

`get_appliances()` returns a fresh `Appliance` snapshot per appliance on every call. The typed
accessors (`state`, `mode`, `mode_state`, `target_temperature`, `humidity`, `bucket_full`,
`filter_needs_attention`, `is_connected`, `wifi_rssi`, ...) parse the reported properties and
return `None` when the model does not report the value. `appliance.get("someKey")` reads anything
they do not cover.

The `set_*` commands encode the protocol's ordering quirks (power-on before mode, re-sending the
setpoint after a cold start, entering Dry mode before setting a humidity target), so callers only
express intent. Each sequence is written once, as a planner in `frigidaire.model`
(`plan_set_mode(appliance, mode)` and so on, which return the actions to send in order), and both
clients send those plans one property per request, so they put the same requests on the wire.

On heat-capable air conditioners, use `client.set_mode(ac, Mode.HEAT)` (awaited on the async
client). Both `mode` and `mode_state` recognize `HEAT` regardless of firmware casing. Availability
depends on the appliance; recognizing the wire value does not imply that every air conditioner
supports heating.

## Sessions and the active-session cap

Electrolux caps the number of active sessions per account (`cas_3403`). Pass a `session_store`
(to `Frigidaire` or to `PasswordBackend`) so a still-valid session survives restarts instead of
lingering server-side. `SessionCapError` is raised when the cap is hit; back off and retry on the
same session. `AuthenticationError` means the credentials were rejected and retrying will not
help. Every error is a `FrigidaireException`, with `status_code` and `error_code` when the API
answered.

See [docs/RATE_LIMITING_AND_TIMEOUTS.md](docs/RATE_LIMITING_AND_TIMEOUTS.md) for write throttling
and timeouts.

## Testing downstream code

`frigidaire.testing` ships fakes for both clients and real sample records for a legacy window AC
(`LEGACY_AC`), a newer portable AC (`TELICA_AC`) and a dehumidifier (`DEHUMIDIFIER`), with
`with_reported(record, **changes)` to vary them.

- `FakeFrigidaire(records)` is the sync `Frigidaire` with the HTTP layer replaced, unchanged from
  1.0: it serves canned appliance records and records every `(setting, value)` it would have sent
  in `commands`. Set `error` to make the next fetch fail; `fetch_count` counts fetch attempts.
- `FakeBackend(records)` is a backend with no network. It records every `(key, value)` it would have
  sent in `commands`. Set `error` to make connects and fetches fail, `command_error` to make
  commands fail, and `supports_live_updates` to `True` to drive `listen()` with
  `await backend.push(record)`. `FakeAsyncFrigidaire(records)` returns
  `AsyncFrigidaire(FakeBackend(records))`; the fake is `client.backend`.

Both run the real command plans and parsing unchanged.
