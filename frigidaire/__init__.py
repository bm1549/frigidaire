"""Frigidaire 2.0 API client"""
from enum import Enum
from requests import Response
from typing import Optional, Dict, Union, List

import json
import logging
import requests
import urllib3
import uuid
import time

# Frigidaire uses a self-signed certificate, which forces us to disable SSL verification
# To keep our logs free of spam, we disable warnings on insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_URL = 'https://api.us.ecp.electrolux.com'

CLIENT_ID = 'Gsdwexj38r1sXSXIPVdxj4DGoU5ZoaI6aW6ZckBI'
USER_AGENT = 'Frigidaire/81 CFNetwork/1206 Darwin/20.1.0'


class FrigidaireException(Exception):
    pass


class Destination(str, Enum):
    AIR_CONDITIONER = "AC1"
    DEHUMIDIFIER = "DH1"


class HaclCode(str, Enum):
    CONNECTIVITY_STATE = "0000"
    APPLIANCE_SERIAL_NUMBER = "0002"
    CONNECTIVITY_NODE_SW_VERSION = "0011"
    LINK_QUALITY_INDICATOR = "0032"
    NETWORK_NAME = "0070"
    APPLIANCE_STATE = "0401"
    POWER_MODE = "0403"
    TEMPERATURE_REPRESENTATION = "0420"
    SLEEP_MODE = "0428"
    AMBIENT_TEMPERATURE = "0430"
    TARGET_TEMPERATURE = "0432"
    ALERT_EVENT = "0470"
    COMPRESSOR_STATE = "04A1"
    BIN_FULL_ALERT = "04E5"
    TARGET_HUMIDITY = "04EA"
    AMBIENT_HUMIDITY = "04EB"
    AC_MODE = "1000"
    AC_FAN_SPEED_SETTING = "1002"
    AC_FAN_SPEED_STATE = "1003"
    AC_CLEAN_AIR_MODE = "1004"
    AC_CLEAN_FILTER_ALERT = "1021"
    AC_COMPRESSOR_COOLING_TIME = "1030"
    AC_COMPRESSOR_HEATING_RUNTIME = "1031"
    AC_ELECTRIC_HEATER_RUNTIME = "1032"
    AC_SCHEDULER_MODE = "1050"
    AC_SCHEDULER_EVENT_COUNT = "1052"
    AC_SCHEDULER_EVENT_SUNDAY = "1053"
    AC_SCHEDULER_EVENT_MONDAY = "1054"
    AC_SCHEDULER_EVENT_TUESDAY = "1055"
    AC_SCHEDULER_EVENT_WEDNESDAY = "1056"
    AC_SCHEDULER_EVENT_THURSDAY = "1057"
    AC_SCHEDULER_EVENT_FRIDAY = "1058"
    AC_SCHEDULER_EVENT_SATURDAY = "1059"
    AC_SCHEDULER_EVENT_ONE_TIME = "105A"


class ContainerId(str, Enum):
    COEFFICIENT = "1"
    EXPONENT = "3"
    UNIT = "0"

    # This isn't the 'real' name, but it makes way more sense
    TEMPERATURE = COEFFICIENT


class ApplianceDetailContainer:
    def __init__(self, args: Dict):
        self.property_name: str = args['propertyName']
        self.t_id: str = args['tId']
        self.group: int = args['group']
        self.number_value: int = args['numberValue']
        self.translation: str = args['translation']


class ApplianceDetailContainers:
    def __init__(self, application_detail_containers: List[ApplianceDetailContainer]):
        self.application_detail_containers: Dict = {container.t_id: container for container in
                                                    application_detail_containers}

    def for_id(self, container_id: ContainerId):
        return self.application_detail_containers.get(container_id)


class ApplianceDetail:
    def __init__(self, args: Dict):
        self.string_value: Optional[str] = args.get('stringValue')
        self.number_value: Optional[int] = args.get('numberValue')
        self.spk_timestamp: int = args['spkTimestamp']
        self.description: str = args['description']
        self.hacl_code: str = args['haclCode']
        self.source: str = args['source']
        self.containers: ApplianceDetailContainers = ApplianceDetailContainers(
            list(map(ApplianceDetailContainer, args['containers'])))

    def __eq__(self, other):
        if isinstance(other, int):
            return self.number_value == other
        elif isinstance(other, str):
            return self.string_value == other
        return super().__eq__(other)


class ApplianceDetails:
    def __init__(self, appliance_details: List[ApplianceDetail]):
        self.appliance_details: Dict = {detail.hacl_code: detail for detail in appliance_details}

    def for_code(self, hacl_code: HaclCode) -> Optional[ApplianceDetail]:
        return self.appliance_details.get(hacl_code)


class Appliance:
    def __init__(self, args: Dict):
        self.appliance_type: str = args['appliance_type']
        self.appliance_id: str = args['appliance_id']
        self.pnc: str = args['pnc']
        self.elc: str = args['elc']
        self.sn: str = args['sn']
        self.mac: str = args['mac']
        self.cpv: str = args['cpv']
        self.nickname: str = args['nickname']
        # Assume a device is an AC until overridden
        self.destination = Destination.AIR_CONDITIONER

    @property
    def query_string(self) -> str:
        params = [
            f'elc={self.elc}',
            f'sn={self.sn}',
            f'pnc={self.pnc}',
            f'mac={self.mac}',  # This isn't necessary for appliance details, but it is for executing an action
        ]

        return '&'.join(params)


class Component(dict):
    def __init__(self, name: str, value: Union[int, str]):
        dict.__init__(self, name=name, value=value)


class Unit(str, Enum):
    FAHRENHEIT = "Fahrenheit"
    CELSIUS = "Celsius"


class Power(int, Enum):
    ON = 1
    OFF = 0


class Mode(int, Enum):
    # Air Conditioner
    OFF = 0
    COOL = 1
    FAN = 3
    ECO = 4
    # Dehumidifier
    DRY = 5
    AUTO = 6
    CONTINUOUS = 8
    QUIET = 9


class FanSpeed(int, Enum):
    # Only HIGH and LOW apply to dehumidifiers
    OFF = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 4
    AUTO = 7


class ConnectivityState(str, Enum):
    CONNECTED = 'connect'
    DISCONNECTED = 'disconnect'


class Action:
    @classmethod
    def set_power(cls, power: Power) -> List[Component]:
        return [Component(HaclCode.POWER_MODE, power)]

    @classmethod
    def set_mode(cls, mode: Mode) -> List[Component]:
        return [Component(HaclCode.AC_MODE, mode)]

    @classmethod
    def set_fan_speed(cls, fan_speed: FanSpeed) -> List[Component]:
        return [Component(HaclCode.AC_FAN_SPEED_SETTING, fan_speed)]

    @classmethod
    def set_humidity(cls, humidity: int) -> List[Component]:
        if humidity < 35 or humidity > 85:
            raise FrigidaireException("Humidity must be between 35 and 85 percent, inclusive")

        return [Component(HaclCode.TARGET_HUMIDITY, humidity)]

    @classmethod
    def set_temperature(cls, temperature: int) -> List[Component]:
        # This is a restriction set by Frigidaire
        if temperature < 60 or temperature > 90:
            raise FrigidaireException("Temperature must be between 60 and 90 degrees, inclusive")

        return [
            Component(HaclCode.TARGET_TEMPERATURE, "Container"),
            Component(ContainerId.COEFFICIENT, temperature),
            # This is the actual temperature, the rest is some required nonsense
            Component(ContainerId.EXPONENT, 0),
            Component(ContainerId.UNIT, 1),
        ]


class Frigidaire:
    """
    An API for interfacing with Frigidaire Air Conditioners
    This was reverse-engineered from the Frigidaire 2.0 App
    """

    def __init__(self, username: str, password: str, session_key: Optional[str] = None, timeout: Optional[float] = None):
        """
        Initializes a new instance of the Frigidaire API and authenticates against it
        :param username: The username to login to Frigidaire. Generally, this is an email
        :param password: The password to login to Frigidaire
        :param session_key: The previously authenticated session key to connect to Frigidaire. If not specified,
                            authentication is required
        :param timeout: The amount of time in seconds to wait before timing out a request
        """
        self.username = username
        self.password = password
        self.device_id: str = str(uuid.uuid4())
        self.session_key: Optional[str] = session_key
        self.timeout: Optional[float] = timeout

        self.authenticate()

    def test_connection(self) -> None:
        """
        Tests for successful connectivity to the Frigidaire server
        :return:
        """
        self.get_request("/config-files/haclmap/latest_version")

    def authenticate(self) -> None:
        """
        Authenticates with the Frigidaire API

        This will re-authenticate if the session key is deemed invalid

        Will throw an exception if the authentication request fails or returns an unexpected response
        :return:
        """
        if self.session_key:
            logging.debug('Authentication requested but session key is present, testing session key')
            try:
                self.test_connection()
                logging.debug('Session key is still valid, doing nothing')
                return None
            except (FrigidaireException, ConnectionError):
                logging.debug('Session key is invalid, re-authenticating')
                self.session_key = None

        data = {
            'username': self.username,
            'password': self.password,
            'deviceId': self.device_id,
            'brand': 'Frigidaire',
            'country': 'US',
        }

        auth_response = self.post_request('/authentication/authenticate', data)

        if not auth_response.get('sessionKey'):
            raise FrigidaireException(f'Failed to authenticate, sessionKey was not in response: {auth_response}')

        logging.debug('Authentication successful, storing new session key')

        self.session_key: Optional[str] = auth_response['sessionKey']

    def re_authenticate(self) -> None:
        """
        Removes the session_key and tries to authenticate again
        :return:
        """
        self.session_key = None
        self.authenticate()

    def get_appliances(self) -> List[Appliance]:
        """
        Uses the Frigidaire API to fetch the list of appliances
        Will authenticate if the request fails
        :return: The appliances that are associated with the Frigidaire account
        """
        logging.debug('Listing appliances')

        def generate_appliance(raw_appliance: Union[Dict, List]) -> Appliance:
            """
            Generates an appliance given a raw_appliance. This will make a second call to the Frigidaire appliance
            details to figure out what source we should be using. We discard the rest of the response from appliance
            details since everything else (except for source) is subject to change later on
            :param raw_appliance: The raw output of the Frigidaire API for the appliance
            :return: The appliance augmented with a destination
            """
            appliance = Appliance(raw_appliance)
            appliance_details = self.get_appliance_details(appliance)
            appliance.destination = appliance_details.for_code(HaclCode.AC_MODE).source
            return appliance

        def get_appliances_inner():
            """
            Actually calls the API for Frigidaire and creates an Appliance. This is useful because we'll sometimes need
            to re-authenticate
            :return: The appliances that are associated with the Frigidaire account
            """
            appliances = self.get_request(
                f'/user-appliance-reg/users/{self.username}/appliances?country=US&includeFields=true'
            )

            return list(map(generate_appliance, appliances))

        try:
            return get_appliances_inner()
        except FrigidaireException:
            logging.debug('Listing appliances failed - attempting to re-authenticate')
            self.re_authenticate()
            return get_appliances_inner()

    def get_appliance_details(self, appliance: Appliance) -> ApplianceDetails:
        """
        Uses the Frigidaire API to fetch details for a given appliance
        Will authenticate if the request fails
        :param appliance: The appliance to request from the API
        :return: The details for the passed in appliance
        """
        logging.debug(f'Getting appliance details for appliance {appliance.nickname}')

        try:
            details = self.get_request(f'/elux-ms/appliances/latest?{appliance.query_string}&includeSubcomponents=true')
            return ApplianceDetails(list(map(ApplianceDetail, details)))
        except FrigidaireException:
            self.re_authenticate()
            details = self.get_request(f'/elux-ms/appliances/latest?{appliance.query_string}&includeSubcomponents=true')
            return ApplianceDetails(list(map(ApplianceDetail, details)))

    def execute_action(self, appliance: Appliance, action: List[Component]) -> None:
        """
        Executes any defined action on a given appliance
        Will authenticate if the request fails
        :param appliance: The appliance to perform the action on
        :param action: The action to be performed
        :return:
        """
        data = {
            'components': action,
            'timestamp': str(int(time.time())),
            'operationMode': 'EXE',
            'version': 'ad',
            'source': 'RP1',
            'destination': appliance.destination,
        }

        try:
            self.post_request(f'/commander/remote/sendjson?{appliance.query_string}', data)
        except FrigidaireException:
            self.re_authenticate()
            self.post_request(f'/commander/remote/sendjson?{appliance.query_string}', data)

    @property
    def headers(self):
        """
        Generates the headers that should be sent on every request to the Frigidaire API
        :return:
        """
        return {
            'session_token': self.session_key,
            'x-ibm-client-id': CLIENT_ID,
            'x-api-key': CLIENT_ID,
            'user-agent': USER_AGENT,
            'content-type': 'application/json',
            'accept': '*/*',
            'accept-language': 'en-us',
            'authorization': 'Basic ' + CLIENT_ID,
        }

    @staticmethod
    def parse_response(response: Response) -> Dict:
        """
        Parses a response from the Frigidaire API
        :param response: The raw response from the requests lib
        :return: The data in the response, if the response was successful and there is data present
        """
        if response.status_code != 200:
            raise FrigidaireException(f'Request failed with status {response.status_code}: {response.content}')

        response_dict = response.json()

        if response_dict.get('status') != 'OK' or 'data' not in response_dict:
            raise FrigidaireException(f'Unexpected response from API: {response.content}')

        return response_dict['data']

    def get_request(self, path: str) -> Union[Dict, List]:
        """
        Makes a get request to the Frigidaire API and parses the result
        :param path: The path to the resource, including query params
        :return: The contents of 'data' in the resulting json
        """
        response = requests.get(f'{API_URL}{path}', headers=self.headers, verify=False, timeout=self.timeout)
        return self.parse_response(response)

    def post_request(self, path: str, data: Dict) -> Union[Dict, List]:
        """
        Makes a post request to the Frigidaire API and parses the result
        :param path: The path to the resource, including query params
        :param data: The data to include in the body of the request
        :return: The contents of 'data' in the resulting json
        """
        response = requests.post(f'{API_URL}{path}', data=json.dumps(data), headers=self.headers, verify=False, timeout=self.timeout)
        return self.parse_response(response)
