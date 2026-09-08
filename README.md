# Frigidaire Python API

A Python client for the Frigidaire 2.0 (Electrolux) cloud API, reverse-engineered from the mobile
app. It drives Frigidaire Wi-Fi air conditioners and dehumidifiers, and is the library behind the
[Home Assistant Frigidaire integration](https://github.com/bm1549/home-assistant-frigidaire).

## Quickstart

```python
from frigidaire import Frigidaire, JsonFileSessionStore, Mode

client = Frigidaire("email", "password", session_store=JsonFileSessionStore("session.json"))

for appliance in client.get_appliances():
    print(appliance, appliance.state, appliance.mode, appliance.ambient_temperature, appliance.temperature_unit)

ac = client.get_appliances()[0]
client.set_mode(ac, Mode.COOL)
client.set_temperature(ac, 72)
```

`get_appliances()` returns a fresh `Appliance` snapshot per appliance on every call. The typed
accessors (`state`, `mode`, `mode_state`, `target_temperature`, `humidity`, `bucket_full`,
`filter_needs_attention`, `is_connected`, `wifi_rssi`, ...) parse the reported properties and
return `None` when the model does not report the value. `appliance.get("someKey")` reads anything
they do not cover.

The `set_*` commands encode the protocol's ordering quirks (power-on before mode, re-sending the
setpoint after a cold start, entering Dry mode before setting a humidity target), so callers only
express intent.

## Sessions and the active-session cap

Electrolux caps the number of active sessions per account (`cas_3403`). Pass a `session_store`
so a still-valid session survives restarts instead of lingering server-side. `SessionCapError` is
raised when the cap is hit; back off and retry on the same session. `AuthenticationError` means
the credentials were rejected and retrying will not help.

See [docs/RATE_LIMITING_AND_TIMEOUTS.md](docs/RATE_LIMITING_AND_TIMEOUTS.md) for write throttling
and timeouts.

## Testing downstream code

`frigidaire.testing.FakeFrigidaire` is a `Frigidaire` with the HTTP layer replaced: it serves canned
appliance records and records every command it would have sent. Sample records for a legacy window
AC, a newer portable AC and a dehumidifier ship alongside it.
