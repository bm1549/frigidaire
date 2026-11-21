# Frigidaire Python API

A Python client for the Frigidaire 2.0 (Electrolux) cloud API, reverse-engineered from the mobile
app. It drives Frigidaire Wi-Fi air conditioners and dehumidifiers, and is the library behind the
[Home Assistant Frigidaire integration](https://github.com/bm1549/home-assistant-frigidaire).

## Quickstart

The client is async. Build it from a backend, the way the account signs in, and connect:

```python
import asyncio

from frigidaire import Frigidaire, JsonFileSessionStore, Mode, PasswordBackend


async def main() -> None:
    client = Frigidaire(PasswordBackend("email", "password", session_store=JsonFileSessionStore("session.json")))
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

`PasswordBackend` signs in with the email and password of the Frigidaire app. Its HTTP code is
blocking and runs on a worker thread, so it never stalls the event loop. It has no live updates:
poll `get_appliances()`, or `refresh(appliance)` for one appliance.

`get_appliances()` returns a fresh `Appliance` snapshot per appliance on every call. The typed
accessors (`state`, `mode`, `mode_state`, `target_temperature`, `humidity`, `bucket_full`,
`filter_needs_attention`, `is_connected`, `wifi_rssi`, ...) parse the reported properties and
return `None` when the model does not report the value. `appliance.get("someKey")` reads anything
they do not cover.

The `set_*` commands encode the protocol's ordering quirks (power-on before mode, re-sending the
setpoint after a cold start, entering Dry mode before setting a humidity target), so callers only
express intent. They send one property per request, the same way on every backend.

On heat-capable air conditioners, use `await client.set_mode(ac, Mode.HEAT)`. Both `mode` and
`mode_state` recognize `HEAT` regardless of firmware casing. Availability depends on the appliance;
recognizing the wire value does not imply that every air conditioner supports heating.

## Sessions and the active-session cap

Electrolux caps the number of active sessions per account (`cas_3403`). Pass a `session_store`
to `PasswordBackend` so a still-valid session survives restarts instead of lingering server-side.
`SessionCapError` is raised when the cap is hit; back off and retry on the same session.
`AuthenticationError` means the credentials were rejected and retrying will not help.

See [docs/RATE_LIMITING_AND_TIMEOUTS.md](docs/RATE_LIMITING_AND_TIMEOUTS.md) for write throttling
and timeouts.

## Errors

Every error is a `FrigidaireException`, with `status_code` and `error_code` when the API answered.
`QuotaExceededError` means the request quota is used up; wait `retry_after` seconds (when given)
before trying again. `CommandRejectedError` means the appliance refused a command in its current
state, for example a target humidity outside Dry mode.

## Testing downstream code

`frigidaire.testing.FakeBackend` is a backend with no network: it serves canned appliance records
and records every `(key, value)` it would have sent in `commands`. Set `error` to make connects and
fetches fail, `command_error` to make commands fail, and `supports_live_updates` to `True` to drive
`listen()` with `await backend.push(record)`. `FakeFrigidaire(records)` returns
`Frigidaire(FakeBackend(records))`, so the real command sequences and parsing run unchanged. Sample
records for a legacy window AC (`LEGACY_AC`), a newer portable AC (`TELICA_AC`) and a dehumidifier
(`DEHUMIDIFIER`) ship alongside it, with `with_reported(record, **changes)` to vary them.
