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

## API key sign-in (beta)

`ApiKeyBackend` uses the official Electrolux Group developer API, through the
`electrolux-group-developer-sdk` package (pinned to 0.7.0). It is the option for accounts that
sign in with Google or Apple and so have no password. It is in beta: it is new, the SDK is
pre-1.0, and how the official API reports some appliances may still differ from the app's API.

It needs three values, all from the [Electrolux Group developer portal](https://developer.electrolux.one/).
Sign in there with the account your appliances are on, then copy:

- the **API key**,
- the **access token**, and
- the **refresh token** issued with it.

```python
from frigidaire import ApiKeyBackend, Frigidaire


def save_tokens(access_token: str, refresh_token: str) -> None:
    # Store both, replacing the previous pair.
    ...


client = Frigidaire(ApiKeyBackend(api_key, access_token, refresh_token, on_tokens=save_tokens))
await client.connect()
print(await client.account_email())
```

The access token expires after a while, and the backend refreshes it with the refresh token.
**Refresh tokens are single-use.** Each refresh returns a new pair and the old refresh token stops
working, so `on_tokens(access_token, refresh_token)` is called with every new pair and you must
store it. `backend.tokens` is the pair in use now. Two programs, or two Home Assistant instances,
that share one token pair log each other out: whichever refreshes second fails. Give each its own
tokens from the portal.

Unlike the password backend it has live updates. `await client.listen(on_update)` runs the API's
event stream until cancelled, reconnecting when it drops, and calls `on_update` with a fresh
`Appliance` snapshot for every pushed change. Poll `get_appliances()` now and then as well, and
after each reconnect, to catch anything the stream missed.

`listen` reports a connection through `on_connect` only once the stream delivers its first event or
has stayed open for `stream_confirm_after` seconds (10 by default), and `on_disconnect` only after
an `on_connect`. The SDK hides the HTTP status of the stream's own response, so a stream that
answers with an HTTP error, a 401 or 403 included, looks like one that drops at once: it is never
reported as connected, and the SDK keeps retrying with backoff up to `stream_max_backoff` seconds
(120 by default). Rejected tokens still end `listen` with `AuthenticationError`, because each
attempt first fetches the stream's configuration with them.

The official API allows a limited number of calls per day. Each appliance's info is fetched once
and cached; after that a full `get_appliances()` costs one call plus one per appliance, and
`refresh(appliance)` costs one. A used-up quota raises `QuotaExceededError`, and rejected tokens
raise `AuthenticationError`; get a new set of values from the portal. A token refresh that gets no
answer, or a server error from the token endpoint, raises a plain `FrigidaireException` instead:
the refresh token was not spent, so try again later. If every appliance's state fails to load,
`get_appliances()` raises rather than returning an empty list.

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
