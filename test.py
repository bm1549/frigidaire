import configparser
import logging

from frigidaire import FanSpeed, Frigidaire, JsonFileSessionStore, Mode

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

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
        credentials.get("username"),
        credentials.get("password"),
        # The session survives re-runs of this script instead of minting a new one each time.
        session_store=JsonFileSessionStore("session.json"),
        # timeout=5,  # uncomment this if testing the request timeout
    )

    appliances = frigidaire.get_appliances()
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
    frigidaire.set_mode(appliance, Mode.COOL)
    frigidaire.set_temperature(appliance, 75)

    logging.debug("fan to medium")
    frigidaire.set_fan_speed(appliance, FanSpeed.MEDIUM)

    logging.debug("vertical swing on, then off")
    frigidaire.set_vertical_swing(appliance, True)
    frigidaire.set_vertical_swing(appliance, False)

    logging.debug("ui lock on, then off")
    frigidaire.set_ui_lock(appliance, True)
    frigidaire.set_ui_lock(appliance, False)

    logging.debug("sleep mode on, then off")
    frigidaire.set_sleep_mode(appliance, True)
    frigidaire.set_sleep_mode(appliance, False)

    # stop time only works while the appliance is on
    logging.debug("set stop time, then clear it")
    frigidaire.set_stop_time(appliance, 1800)
    frigidaire.set_stop_time(appliance, 0)

    # start time only works while the appliance is off
    logging.debug("turn off, set start time, then clear it")
    frigidaire.set_power(appliance, False)
    frigidaire.set_start_time(appliance, 1800)
    frigidaire.set_start_time(appliance, 0)

    # re-read the state after the commands
    appliance = next(a for a in frigidaire.get_appliances() if a.appliance_id == appliance.appliance_id)
    logging.debug("now: state=%s mode=%s", appliance.state, appliance.mode)
