"""The async Frigidaire facade: one API for every backend.

The facade owns everything that does not depend on how the account is reached: parsing records
into :class:`~frigidaire.model.Appliance` snapshots and the command sequences, which encode the
appliances' ordering quirks (power-on first, setpoint last, Dry before a humidity target, an AC's
"auto" is ECO). It sends one property per request, so those quirks behave the same on every
backend.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from .backends.base import Backend
from .exceptions import FrigidaireException
from .model import (
    Action,
    Appliance,
    ApplianceState,
    Component,
    Destination,
    DisplayLight,
    FanSpeed,
    Mode,
    Power,
    SleepMode,
    Unit,
    VerticalSwing,
)

_LOGGER = logging.getLogger(__name__)


def _noop() -> None:
    return None


class Frigidaire:
    """An async client for Frigidaire air conditioners and dehumidifiers.

    Construct it with a backend, for example
    ``Frigidaire(PasswordBackend("email", "password"))``, then ``await connect()``.
    """

    def __init__(self, backend: Backend) -> None:
        self.backend = backend

    def __repr__(self) -> str:
        return f"Frigidaire({self.backend!r})"

    @property
    def supports_live_updates(self) -> bool:
        """Whether :meth:`listen` pushes updates. When ``False``, poll :meth:`get_appliances`."""
        return self.backend.supports_live_updates

    # --- session ---

    async def connect(self) -> None:
        """Sign in, or validate the stored session or tokens."""
        await self.backend.connect()

    async def account_email(self) -> str:
        """The email address of the signed-in account."""
        return await self.backend.account_email()

    async def close(self) -> None:
        """Release the backend's connections."""
        await self.backend.close()

    # --- appliances ---

    async def get_appliances(self) -> list[Appliance]:
        """
        Fetch every appliance on the account, with its current reported state.

        Appliances of a type this library cannot place are skipped with a warning, as are
        malformed records.
        :return: A fresh snapshot of each appliance
        """
        appliances = []
        for record in await self.backend.fetch_records():
            appliance = _parse(record)
            if appliance is not None and appliance.destination is not None:
                appliances.append(appliance)
        return appliances

    async def refresh(self, appliance: Appliance) -> Appliance:
        """Fetch a fresh snapshot of one appliance, for example after a command."""
        record = await self.backend.fetch_record(appliance.appliance_id)
        try:
            return Appliance(record)
        except (KeyError, TypeError) as err:
            raise FrigidaireException(f"Received a malformed record for appliance {appliance.appliance_id}") from err

    async def listen(
        self,
        on_update: Callable[[Appliance], None],
        on_connect: Callable[[], None] = _noop,
        on_disconnect: Callable[[], None] = _noop,
    ) -> None:
        """Stream live updates until cancelled, passing each updated appliance to ``on_update``.

        ``on_connect`` runs each time the stream (re)connects and ``on_disconnect`` each time it
        drops. Raises ``NotImplementedError`` when the backend has no live updates.
        """

        def on_record(record: dict) -> None:
            appliance = _parse(record)
            if appliance is not None and appliance.destination is not None:
                on_update(appliance)

        await self.backend.listen(on_record, on_connect, on_disconnect)

    async def execute_action(self, appliance: Appliance, action: list[Component]) -> None:
        """
        Sends each component of an action to an appliance, one request per component, in order.
        :param appliance: The appliance to perform the action on
        :param action: The components to send
        """
        for component in action:
            await self.backend.send(appliance.appliance_id, component.name, component.value)

    # --- commands ---
    #
    # These encode what the appliances actually need, so callers can express intent
    # ("cool at 72") without knowing the protocol's ordering quirks.

    async def set_power(self, appliance: Appliance, on: bool) -> None:
        await self.execute_action(appliance, Action.set_power(Power.ON if on else Power.OFF))

    async def set_mode(self, appliance: Appliance, mode: Mode) -> None:
        """Select an operating mode, powering the appliance on first.

        Air conditioners: power-on is always sent, because the cloud reports the desired state
        rather than the hardware state. After a failed turn-on it keeps saying RUNNING, so
        gating on it would skip the power command on every retry; power is a set, not a
        toggle, so this is harmless on a unit that really is running. A unit that was off
        forgets its setpoint and engaging the mode restores a default, so the remembered
        setpoint is re-sent last. Mode.AUTO is a dehumidifier value that an AC silently
        ignores; its energy-saving mode is ECO.
        """
        if mode is Mode.OFF:
            await self.execute_action(appliance, Action.set_mode(Mode.OFF))
            return

        if appliance.destination is Destination.AIR_CONDITIONER:
            if mode is Mode.AUTO:
                mode = Mode.ECO
            was_off = appliance.state is ApplianceState.OFF or appliance.mode is Mode.OFF
            await self.set_power(appliance, True)
            await self.execute_action(appliance, Action.set_mode(mode))
            target = appliance.target_temperature
            if was_off and target is not None:
                await self.set_temperature(appliance, int(target))
            return

        if appliance.state is ApplianceState.OFF:
            await self.set_power(appliance, True)
        await self.execute_action(appliance, Action.set_mode(mode))

    async def set_temperature(self, appliance: Appliance, temperature: int, unit: Unit | None = None) -> None:
        """Set the AC setpoint. Defaults to the unit the appliance reports in."""
        unit = unit or appliance.temperature_unit or Unit.FAHRENHEIT
        await self.execute_action(appliance, Action.set_temperature(int(temperature), unit))

    async def set_fan_speed(self, appliance: Appliance, fan_speed: FanSpeed) -> None:
        await self.execute_action(appliance, Action.set_fan_speed(fan_speed))

    async def set_humidity(self, appliance: Appliance, humidity: int) -> None:
        """Set the dehumidifier target. Snaps to 5% steps; the appliance only accepts a target in Dry mode."""
        components = Action.set_humidity(5 * round(humidity / 5))
        await self.set_mode(appliance, Mode.DRY)
        await self.execute_action(appliance, components)

    async def set_sleep_mode(self, appliance: Appliance, on: bool) -> None:
        await self.execute_action(appliance, Action.set_sleep_mode(SleepMode.ON if on else SleepMode.OFF))

    async def set_vertical_swing(self, appliance: Appliance, on: bool) -> None:
        await self.execute_action(appliance, Action.set_vertical_swing(VerticalSwing.ON if on else VerticalSwing.OFF))

    async def set_ui_lock(self, appliance: Appliance, on: bool) -> None:
        await self.execute_action(appliance, Action.set_ui_lock_mode(on))

    async def set_display_light(self, appliance: Appliance, on: bool) -> None:
        await self.execute_action(appliance, Action.set_display_light(DisplayLight.ON if on else DisplayLight.OFF))

    async def set_clean_air_mode(self, appliance: Appliance, on: bool) -> None:
        await self.execute_action(appliance, Action.set_clean_air_mode(on))

    async def set_start_time(self, appliance: Appliance, seconds: int) -> None:
        await self.execute_action(appliance, Action.set_start_time(seconds))

    async def set_stop_time(self, appliance: Appliance, seconds: int) -> None:
        await self.execute_action(appliance, Action.set_stop_time(seconds))


def _parse(record: dict) -> Appliance | None:
    try:
        return Appliance(record)
    except (KeyError, TypeError):
        _LOGGER.warning("Skipping malformed appliance record: %r", record)
        return None
