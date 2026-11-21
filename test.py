import asyncio
import configparser
import logging

from frigidaire import FanSpeed, Frigidaire, JsonFileSessionStore, Mode, PasswordBackend


async def main() -> None:
    # Create a config file at config.ini to reduce the risk of accidentally committing credentials
    # You can use the following contents as a starting point
    """
    [credentials]
    username=email@example.com
    password=password
    """
    config = configparser.ConfigParser()
    config.read("config.ini")
    credentials = config["credentials"] or {}

    frigidaire = Frigidaire(
        PasswordBackend(
            credentials.get("username"),
            credentials.get("password"),
            # The session survives re-runs of this script instead of minting a new one each time.
            session_store=JsonFileSessionStore("session.json"),
            # timeout=5,  # uncomment this if testing the request timeout
        )
    )
    await frigidaire.connect()

    appliances = await frigidaire.get_appliances()
    for appliance in appliances:
        logging.debug(
            "%s: state=%s mode=%s target=%s %s ambient=%s",
            appliance,
            appliance.state,
            appliance.mode,
            appliance.target_temperature,
            appliance.temperature_unit,
            appliance.ambient_temperature,
        )

    # pick one arbitrarily
    appliance = appliances[0]

    logging.debug("cool at 75")
    await frigidaire.set_mode(appliance, Mode.COOL)
    await frigidaire.set_temperature(appliance, 75)

    logging.debug("fan to medium")
    await frigidaire.set_fan_speed(appliance, FanSpeed.MEDIUM)

    logging.debug("vertical swing on, then off")
    await frigidaire.set_vertical_swing(appliance, True)
    await frigidaire.set_vertical_swing(appliance, False)

    logging.debug("ui lock on, then off")
    await frigidaire.set_ui_lock(appliance, True)
    await frigidaire.set_ui_lock(appliance, False)

    logging.debug("sleep mode on, then off")
    await frigidaire.set_sleep_mode(appliance, True)
    await frigidaire.set_sleep_mode(appliance, False)

    # stop time only works while the appliance is on
    logging.debug("set stop time, then clear it")
    await frigidaire.set_stop_time(appliance, 1800)
    await frigidaire.set_stop_time(appliance, 0)

    # start time only works while the appliance is off
    logging.debug("turn off, set start time, then clear it")
    await frigidaire.set_power(appliance, False)
    await frigidaire.set_start_time(appliance, 1800)
    await frigidaire.set_start_time(appliance, 0)

    # re-read the state after the commands
    appliance = await frigidaire.refresh(appliance)
    logging.debug("now: state=%s mode=%s", appliance.state, appliance.mode)

    await frigidaire.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())
