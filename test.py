import configparser
import logging

from frigidaire import Action, Power, Mode, FanSpeed, Frigidaire

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    # Create a config file at config.ini to reduce the risk of accidentally committing credentials
    # You can use the following contents as a starting point
    """
    [credentials]
    username=email@example.com
    password=password
    ; session_key=insert_session_key_here
    ; regional_base_url=https://api.us.ocp.electrolux.one
    """
    config = configparser.ConfigParser()
    config.read('config.ini')
    credentials = config['credentials'] or {}

    username = credentials.get('username')
    password = credentials.get('password')
    session_key = credentials.get('session_key', fallback=None)
    regional_base_url = credentials.get('regional_base_url', fallback=None)

    frigidaire = Frigidaire(
        username,
        password,
        session_key=session_key,
        regional_base_url=regional_base_url,
        # timeout=5,  # uncomment this if testing the request timeout
    )

    # tests connectivity
    logging.debug("tests connectivity")
    frigidaire.test_connection()

    # get appliances
    logging.debug("get appliance")
    appliances = frigidaire.get_appliances()

    # pick one arbitrarily
    appliance = appliances[0]

    # get some details for it
    logging.debug("get details")
    appliance_details = frigidaire.get_appliance_details(appliance)

    # turn on
    logging.debug("turn on")
    frigidaire.execute_action(appliance, Action.set_power(Power.ON))

    # set to cool
    logging.debug("set to cool")
    frigidaire.execute_action(appliance, Action.set_mode(Mode.COOL))

    # set fan to medium
    logging.debug("set fan to medium")
    frigidaire.execute_action(appliance, Action.set_fan_speed(FanSpeed.MEDIUM))

    # set temperature to 75
    logging.debug("set temp to 75")
    frigidaire.execute_action(appliance, Action.set_temperature(75))

    # re-authenticate the connection to get a new session_key
    logging.debug("re-authenticate")
    frigidaire.re_authenticate()

    # turn off
    logging.debug("turn off")
    frigidaire.execute_action(appliance, Action.set_power(Power.OFF))
