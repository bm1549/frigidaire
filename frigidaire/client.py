"""The async client: one API over any backend.

``AsyncFrigidaire`` owns everything that does not depend on how the account is reached: parsing
records into :class:`~frigidaire.model.Appliance` snapshots and sending the command plans from
:mod:`frigidaire.model`, which encode the appliances' ordering quirks (power-on first, setpoint
last, Dry before a humidity target, an AC's "auto" is ECO). It sends one property per request, so
those quirks behave the same on every backend.
"""

from __future__ import annotations

from collections.abc import Callable

from .backends.base import Backend
from .exceptions import FrigidaireException
from .model import (
    Appliance,
    Component,
    FanSpeed,
    Mode,
    Unit,
    parse_appliances,
    plan_set_clean_air_mode,
    plan_set_display_light,
    plan_set_fan_speed,
    plan_set_humidity,
    plan_set_mode,
    plan_set_power,
    plan_set_sleep_mode,
    plan_set_start_time,
    plan_set_stop_time,
    plan_set_temperature,
    plan_set_ui_lock,
    plan_set_vertical_swing,
)


def _noop() -> None:
    return None


class AsyncFrigidaire:
    """An async client for Frigidaire air conditioners and dehumidifiers.

    Construct it with a backend, for example
    ``AsyncFrigidaire(PasswordBackend("email", "password"))``, then ``await connect()``.
    """

    def __init__(self, backend: Backend) -> None:
        self.backend = backend

    def __repr__(self) -> str:
        return f"AsyncFrigidaire({self.backend!r})"

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
        return parse_appliances(await self.backend.fetch_records())

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
            for appliance in parse_appliances([record]):
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

    async def _send_plan(self, appliance: Appliance, plan: list[list[Component]]) -> None:
        for action in plan:
            await self.execute_action(appliance, action)

    # --- commands ---
    #
    # Each sends the plan of the same name from frigidaire.model, where the ordering quirks are
    # documented, so callers can express intent ("cool at 72") without knowing the protocol.

    async def set_power(self, appliance: Appliance, on: bool) -> None:
        await self._send_plan(appliance, plan_set_power(appliance, on))

    async def set_mode(self, appliance: Appliance, mode: Mode) -> None:
        """Select an operating mode, powering the appliance on first; see :func:`~frigidaire.model.plan_set_mode`."""
        await self._send_plan(appliance, plan_set_mode(appliance, mode))

    async def set_temperature(self, appliance: Appliance, temperature: int, unit: Unit | None = None) -> None:
        """Set the AC setpoint. Defaults to the unit the appliance reports in."""
        await self._send_plan(appliance, plan_set_temperature(appliance, temperature, unit))

    async def set_fan_speed(self, appliance: Appliance, fan_speed: FanSpeed) -> None:
        await self._send_plan(appliance, plan_set_fan_speed(appliance, fan_speed))

    async def set_humidity(self, appliance: Appliance, humidity: int) -> None:
        """Set the dehumidifier target. Snaps to 5% steps; the appliance only accepts a target in Dry mode."""
        await self._send_plan(appliance, plan_set_humidity(appliance, humidity))

    async def set_sleep_mode(self, appliance: Appliance, on: bool) -> None:
        await self._send_plan(appliance, plan_set_sleep_mode(appliance, on))

    async def set_vertical_swing(self, appliance: Appliance, on: bool) -> None:
        await self._send_plan(appliance, plan_set_vertical_swing(appliance, on))

    async def set_ui_lock(self, appliance: Appliance, on: bool) -> None:
        await self._send_plan(appliance, plan_set_ui_lock(appliance, on))

    async def set_display_light(self, appliance: Appliance, on: bool) -> None:
        await self._send_plan(appliance, plan_set_display_light(appliance, on))

    async def set_clean_air_mode(self, appliance: Appliance, on: bool) -> None:
        await self._send_plan(appliance, plan_set_clean_air_mode(appliance, on))

    async def set_start_time(self, appliance: Appliance, seconds: int) -> None:
        await self._send_plan(appliance, plan_set_start_time(appliance, seconds))

    async def set_stop_time(self, appliance: Appliance, seconds: int) -> None:
        await self._send_plan(appliance, plan_set_stop_time(appliance, seconds))
