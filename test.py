import logging

from frigidaire import Action, Power, Mode, FanSpeed, Frigidaire, HaclCode, Component

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    username = 'email@example.com'
    password = 'password'
    session_key = 'get_this_from_authenticate'

    frigidaire = Frigidaire(
        username,
        password,
        # session_key,  # uncomment this if testing with an already authenticated session key
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
