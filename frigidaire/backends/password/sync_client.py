"""The synchronous ``Frigidaire`` client of 1.x, signed in with email and password.

It is :class:`~frigidaire.backends.password.transport.PasswordTransport` plus the appliance API
the library has always had: ``get_appliances``, ``execute_action`` and the ``set_*`` commands.
The commands send the plans from :mod:`frigidaire.model`, the same ones ``AsyncFrigidaire``
sends, so both clients put identical requests on the wire. It lives in the password package and
goes with it; new code should use ``AsyncFrigidaire(PasswordBackend(...))``.
"""

from __future__ import annotations

import logging

from ...model import (
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
from .transport import PasswordTransport

_LOGGER = logging.getLogger(__name__)


class Frigidaire(PasswordTransport):
    """
    An API for interfacing with Frigidaire air conditioners and dehumidifiers.
    This was reverse-engineered from the Frigidaire 2.0 App.

    Blocking: every call makes HTTP requests on the calling thread. The constructor takes the
    username, password and keyword arguments of :class:`PasswordTransport` and authenticates.
    """

    # --- appliances ---

    def get_appliances(self) -> list[Appliance]:
        """
        Fetch every appliance on the account, with its current reported state, in one request.
        Will authenticate if the request fails.

        Appliances of a type this library cannot place are skipped with a warning, as are
        malformed records.
        :return: A fresh snapshot of each appliance
        """
        _LOGGER.debug("Listing appliances")
        return self._with_reauth(lambda: parse_appliances(self._fetch_raw_appliances()))

    def execute_action(self, appliance: Appliance, action: list[Component]) -> None:
        """
        Sends each component of an action to an appliance, one request per component.
        Will authenticate if the request fails.
        :param appliance: The appliance to perform the action on
        :param action: The components to send
        """
        for component in action:
            self.send_command(appliance.appliance_id, component.name, component.value)

    def _send_plan(self, appliance: Appliance, plan: list[list[Component]]) -> None:
        for action in plan:
            self.execute_action(appliance, action)

    # --- commands ---
    #
    # Each sends the plan of the same name from frigidaire.model, where the ordering quirks are
    # documented, so callers can express intent ("cool at 72") without knowing the protocol.

    def set_power(self, appliance: Appliance, on: bool) -> None:
        self._send_plan(appliance, plan_set_power(appliance, on))

    def set_mode(self, appliance: Appliance, mode: Mode) -> None:
        """Select an operating mode, powering the appliance on first; see :func:`~frigidaire.model.plan_set_mode`."""
        self._send_plan(appliance, plan_set_mode(appliance, mode))

    def set_temperature(self, appliance: Appliance, temperature: int, unit: Unit | None = None) -> None:
        """Set the AC setpoint. Defaults to the unit the appliance reports in."""
        self._send_plan(appliance, plan_set_temperature(appliance, temperature, unit))

    def set_fan_speed(self, appliance: Appliance, fan_speed: FanSpeed) -> None:
        self._send_plan(appliance, plan_set_fan_speed(appliance, fan_speed))

    def set_humidity(self, appliance: Appliance, humidity: int) -> None:
        """Set the dehumidifier target. Snaps to 5% steps; the appliance only accepts a target in Dry mode."""
        self._send_plan(appliance, plan_set_humidity(appliance, humidity))

    def set_sleep_mode(self, appliance: Appliance, on: bool) -> None:
        self._send_plan(appliance, plan_set_sleep_mode(appliance, on))

    def set_vertical_swing(self, appliance: Appliance, on: bool) -> None:
        self._send_plan(appliance, plan_set_vertical_swing(appliance, on))

    def set_ui_lock(self, appliance: Appliance, on: bool) -> None:
        self._send_plan(appliance, plan_set_ui_lock(appliance, on))

    def set_display_light(self, appliance: Appliance, on: bool) -> None:
        self._send_plan(appliance, plan_set_display_light(appliance, on))

    def set_clean_air_mode(self, appliance: Appliance, on: bool) -> None:
        self._send_plan(appliance, plan_set_clean_air_mode(appliance, on))

    def set_start_time(self, appliance: Appliance, seconds: int) -> None:
        self._send_plan(appliance, plan_set_start_time(appliance, seconds))

    def set_stop_time(self, appliance: Appliance, seconds: int) -> None:
        self._send_plan(appliance, plan_set_stop_time(appliance, seconds))
