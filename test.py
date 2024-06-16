import configparser
import logging

from frigidaire import Action, Power, Mode, FanSpeed, Frigidaire

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    # Create a config file at config.ini to reduce the risk of accidentally committing credentials
    # You can use the following contents as a starting point
    """
    [credentials]
    Username=email@example.com
    Password=password
    """
    config = configparser.ConfigParser()
    config.read('config.ini')
    credentials = config['credentials'] or {}

    username = credentials.get('username')
    password = credentials.get('password')
    session_key = credentials.get('session_key', fallback=None)

    frigidaire = Frigidaire(
        username,
        password,
        # session_key,  # uncomment this if testing with an already authenticated session key
        # timeout=5,  # uncomment this if testing the request timeout
    )

    # tests connectivity
    frigidaire.test_connection()

    # get appliances
    appliances = frigidaire.get_appliances()

    # pick one arbitrarily
    appliance = appliances[0]

    # get some details for it
    appliance_details = frigidaire.get_appliance_details(appliance)

    # turn on
    frigidaire.execute_action(appliance, Action.set_power(Power.ON))

    # set to cool
    frigidaire.execute_action(appliance, Action.set_mode(Mode.COOL))

    # set fan to medium
    frigidaire.execute_action(appliance, Action.set_fan_speed(FanSpeed.MEDIUM))

    # set temperature to 75
    frigidaire.execute_action(appliance, Action.set_temperature(75))

    # re-authenticate the connection to get a new session_key
    frigidaire.re_authenticate()

    # turn off
    frigidaire.execute_action(appliance, Action.set_power(Power.OFF))
