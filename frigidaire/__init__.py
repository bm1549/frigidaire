"""Frigidaire 2.0 API client"""
from enum import Enum
from requests import Response
from typing import Optional, Dict, Union, List

import gzip
import json
import logging
import random
import requests
import urllib3
from urllib.parse import quote_plus
from urllib.parse import urlencode
import uuid
import time

from  .signature_generator import get_signature

# Frigidaire uses a self-signed certificate, which forces us to disable SSL verification
# To keep our logs free of spam, we disable warnings on insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GLOBAL_API_URL = 'https://api.ocp.electrolux.one'

FRIGIDAIRE_API_KEY = 'UcGF9pmUMKUqBL6qcQvTu4K4WBmQ5KJqJXprCTdc'
CLIENT_SECRET = '26SGRupOJaxv4Y1npjBsScjJPuj7f8YTdGxJak3nhAnowCStsBAEzKtrEHsgbqUyh90KFsoty7xXwMNuLYiSEcLqhGQryBM26i435hncaLqj5AuSvWaGNRTACi7ba5yu'
CLIENT_ID = 'FrigidaireOneApp'
FRIGIDAIRE_USER_AGENT = 'Ktor client'
AUTH_USER_AGENT = 'Dalvik/2.1.0 (Linux; U; Android 12; sdk_gphone64_x86_64 Build/SE1A.220826.008)'


class FrigidaireException(Exception):
    pass


class Destination(str, Enum):
    AIR_CONDITIONER = "AC"
    DEHUMIDIFIER = "DH" # TODO: Not tested


class Setting(str, Enum):
    """
    Writeable settings that are known valid names of Components.
    These can be passed to the execute_action() API together with a target value
    to change settings.
    """
    FAN_SPEED = "fanSpeedSetting"
    EXECUTE_COMMAND = "executeCommand"
    MODE = "mode"
    SLEEP_MODE = "sleepMode"
    TARGET_TEMPERATURE_C = "targetTemperatureC"
    TARGET_TEMPERATURE_F = "targetTemperatureF"
    TEMPERATURE_REPRESENTATION = "temperatureRepresentation"
    UI_LOCK_MODE = "uiLockMode"
    VERTICAL_SWING = "verticalSwing"


class Detail(str, Enum):
    """
    Readable details that are known to be present in some products.
    """
    ALERTS = "alerts"
    AMBIENT_TEMPERATURE_C = "ambientTemperatureC"
    AMBIENT_TEMPERATURE_F = "ambientTemperatureF"
    APPLIANCE_STATE = "applianceState"
    APPLIANCE_UI_SW_VERSION = "applianceUiSwVersion"
    FAN_SPEED = "fanSpeedSetting"
    FAN_SPEED_STATE = "fanSpeedState"
    FILTER_STATE = "filterState"
    MODE = "mode"
    NETWORK_INTERFACE = "networkInterface"
    SLEEP_MODE = "sleepMode"
    TARGET_TEMPERATURE_C = "targetTemperatureC"
    TARGET_TEMPERATURE_F = "targetTemperatureF"
    TEMPERATURE_REPRESENTATION = "temperatureRepresentation"
    UI_LOCK_MODE = "uiLockMode"
    VERTICAL_SWING = "verticalSwing"


class Appliance:
    def __init__(self, args: Dict):
        self.appliance_type: str = args['properties']['reported']['applianceInfo']['applianceType']
        self.appliance_id: str = args['applianceId']
        self.nickname: str = args['applianceData']['applianceName']
        self.destination = Destination(self.appliance_type)


class Component:
    def __init__(self, name: Union[str, Setting], value: Union[int, str]):
        """
        Create a new Component to specify a setting with a name and value.
        Note: String names are discouraged but allowed since not all settings are known at this time.

        :param name: Name of the setting (Setting or a string).
        :param value: Value of the setting (string or int)
        """
        if isinstance(name, Setting):
            name = name.value
        self.name = name
        self.value = value


class Unit(str, Enum):
    FAHRENHEIT = "FAHRENHEIT"
    CELSIUS = "CELSIUS"


class Power(str, Enum):
    ON = 'ON'
    OFF = 'OFF'


class Mode(str, Enum):
    # Air Conditioner
    OFF = 'OFF'
    COOL = 'COOL'
    FAN = 'FANONLY'
    ECO = 'ECO'
    # Dehumidifier (TODO: not tested with OCP API, minor tweaks may be required)
    DRY = 'DRY'
    AUTO = 'AUTO'
    CONTINUOUS = 'CONTINUOUS'
    QUIET = 'QUIET'


class FanSpeed(str, Enum):
    # Only HIGH and LOW apply to dehumidifiers
    LOW = 'LOW'
    MEDIUM = 'MIDDLE'
    HIGH = 'HIGH'
    AUTO = 'AUTO'


class Action:
    @classmethod
    def set_power(cls, power: Power) -> List[Component]:
        return [Component(Setting.EXECUTE_COMMAND, power)]

    @classmethod
    def set_mode(cls, mode: Mode) -> List[Component]:
        return [Component(Setting.MODE, mode)]

    @classmethod
    def set_fan_speed(cls, fan_speed: FanSpeed) -> List[Component]:
        return [Component(Setting.FAN_SPEED_SETTING, fan_speed)]

    @classmethod
    def set_humidity(cls, humidity: int) -> List[Component]:
        if humidity < 35 or humidity > 85:
            raise FrigidaireException("Humidity must be between 35 and 85 percent, inclusive")

        raise FrigidaireException("Humidity setting not implemented for OCP API (setting key unknown)")

    @classmethod
    def set_temperature(cls, temperature: int) -> List[Component]:
        # This is a restriction set by Frigidaire
        if temperature < 60 or temperature > 90:
            raise FrigidaireException("Temperature must be between 60 and 90 degrees, inclusive")

        return [
            Component(Setting.TEMPERATURE_REPRESENTATION, Unit.FAHRENHEIT),
            Component(Setting.TARGET_TEMPERATURE_F, temperature),
        ]


def _generate_nonce() -> str:
    """
    Generate a one-off random token to preserve the security of encrypted communication
    """
    return f'{str(int(time.time()))}_-{str(random.getrandbits(32))}'


class Frigidaire:
    """
    An API for interfacing with Frigidaire Air Conditioners
    This was reverse-engineered from the Frigidaire 2.0 App
    """

    def __init__(self, username: str, password: str, session_key: Optional[str] = None, timeout: Optional[float] = None, regional_base_url: Optional[str] = None):
        """
        Initializes a new instance of the Frigidaire API and authenticates against it
        :param username: The username to login to Frigidaire. Generally, this is an email
        :param password: The password to login to Frigidaire
        :param session_key: The previously authenticated session key to connect to Frigidaire. If not specified,
                            authentication is required
        :param timeout: The amount of time in seconds to wait before timing out a request
        :param regional_base_url: Regional base URL for the API user account
                            (e.g., https://api.us.ocp.electrolux.one for U.S. accounts). If not specified,
                            authentication is required
        """
        self.username = username
        self.password = password
        self.session_key: Optional[str] = session_key
        self.timeout: Optional[float] = timeout
        self.regional_base_url = regional_base_url

        self.authenticate()

    def get_headers_frigidaire(self, method: str, include_bearer_token: bool) -> Dict[str, str]:
        to_return = {
            "x-api-key": FRIGIDAIRE_API_KEY,
            "Authorization": "Bearer" if not (self.session_key and include_bearer_token) else f"Bearer {self.session_key}",
            "Accept": "application/json",
            "Accept-Charset": "UTF-8",
            "User-Agent": FRIGIDAIRE_USER_AGENT
        }
        if method.upper() != "GET":
            to_return["Content-Type"] = "application/json"
        return to_return

    def get_headers_auth(self, method: str) -> Dict[str, str]:
        to_return = {
            "User-Agent": AUTH_USER_AGENT,
            "Accept-Encoding": "gzip",
            "connection": "close"
        }
        if method.upper() != "GET":
            to_return["Content-Type"] = "application/x-www-form-urlencoded"
        return to_return

    def test_connection(self) -> None:
        """
        Tests for successful connectivity to the Frigidaire server
        :return:
        """
        return self.get_request(self.regional_base_url, "/one-account-user/api/v1/users/current?countryDetails=true", self.get_headers_frigidaire("GET", include_bearer_token=True))


    def authenticate(self) -> None:
        """
        Authenticates with the Frigidaire API

        This will re-authenticate if the session key is deemed invalid

        Will throw an exception if the authentication request fails or returns an unexpected response
        :return:
        """

        if not self.regional_base_url:
            self.session_key = None

        ## Remember to include "Context-Brand: frigidaire" in the headers for the "/api/v1/identity-providers" and "/api/v1/users/current" calls
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
            'grantType': 'client_credentials',
            'clientId': CLIENT_ID,
            'clientSecret': CLIENT_SECRET,
            'scope': ''
        }
        session_key_response = self.post_request(GLOBAL_API_URL, '/one-account-authorization/api/v1/token', self.get_headers_frigidaire("POST", include_bearer_token=False), data)
        self.session_key = session_key_response['accessToken']

        identity_providers_response = self.get_request(GLOBAL_API_URL, f'/one-account-user/api/v1/identity-providers?brand=frigidaire&email={quote_plus(self.username)}&loginType=OTP', self.get_headers_frigidaire("GET", include_bearer_token=True))
        identity_domain = identity_providers_response[0]['domain']
        identity_api_key = identity_providers_response[0]['apiKey']
        self.regional_base_url = identity_providers_response[0]['httpRegionalBaseUrl']

        data = {
            "apiKey": identity_api_key,
            "format": "json",
            "httpStatusCodes": "false",
            "nonce": _generate_nonce(),
            "sdk": "Android_6.2.1",
            "targetEnv": "mobile"
        }
        get_ids_response = self.post_request(f'https://socialize.{identity_domain}', '/socialize.getIDs', self.get_headers_auth("POST"), data, form_encoding=True)

        auth_gmid = get_ids_response['gmid']
        auth_ucid = get_ids_response['ucid']

        data = {
            "apiKey": identity_api_key,
            "format": "json",
            "gmid": auth_gmid,
            "httpStatusCodes": "false",
            "loginID": self.username,
            "nonce": _generate_nonce(),
            "password": self.password,
            "sdk": "Android_6.2.1",
            "targetEnv": "mobile",
            "ucid": auth_ucid
        }
        login_response = self.post_request(f'https://accounts.{identity_domain}', '/accounts.login', self.get_headers_auth("POST"), data, form_encoding=True)

        auth_session_token = login_response['sessionInfo']['sessionToken']
        auth_session_secret = login_response['sessionInfo']['sessionSecret']

        data = {
            "apiKey": identity_api_key,
            "fields": "country",
            "format": "json",
            "gmid": auth_gmid,
            "httpStatusCodes": "false",
            "nonce": _generate_nonce(),
            "oauth_token": auth_session_token,
            "sdk": "Android_6.2.1",
            "targetEnv": "mobile",
            "timestamp": str(int(time.time())),
            "ucid": auth_ucid
        }
        data["sig"] = get_signature(auth_session_secret, "POST", f'https://accounts.{identity_domain}/accounts.getJWT', data)
        jwt_response = self.post_request(f'https://accounts.{identity_domain}', '/accounts.getJWT', self.get_headers_auth("POST"), data, form_encoding=True)

        auth_jwt = jwt_response['id_token']

        data = {
            "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
            "clientId": CLIENT_ID,
            "idToken": auth_jwt,
            "scope": ""
        }
        frigidaire_auth_response = self.post_request(self.regional_base_url, '/one-account-authorization/api/v1/token', self.get_headers_frigidaire("POST", include_bearer_token=False), data)

        if not frigidaire_auth_response.get('accessToken'):
            raise FrigidaireException(f'Failed to authenticate, accessToken was not in response: {frigidaire_auth_response}')

        logging.debug('Authentication successful, storing new session key')
        self.session_key = frigidaire_auth_response['accessToken']

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
            return Appliance(raw_appliance)

        def get_appliances_inner():
            """
            Actually calls the API for Frigidaire and creates an Appliance. This is useful because we'll sometimes need
            to re-authenticate
            :return: The appliances that are associated with the Frigidaire account
            """
            appliances = self.get_request(self.regional_base_url, 
                '/appliance/api/v2/appliances?includeMetadata=true', self.get_headers_frigidaire("GET", include_bearer_token=True))

            return list(map(generate_appliance, appliances))

        try:
            return get_appliances_inner()
        except FrigidaireException:
            logging.debug('Listing appliances failed - attempting to re-authenticate')
            self.re_authenticate()
            return get_appliances_inner()

    def get_appliance_details(self, appliance: Appliance) -> Dict:
        """
        Uses the Frigidaire API to fetch details for a given appliance
        Will authenticate if the request fails
        :param appliance: The appliance to request from the API
        :return: The details for the passed in appliance
        """
        logging.debug(f'Getting appliance details for appliance {appliance.nickname}')

        try:
            appliances = self.get_request(self.regional_base_url, 
                '/appliance/api/v2/appliances?includeMetadata=true', self.get_headers_frigidaire("GET", include_bearer_token=True))
        except FrigidaireException:
            self.re_authenticate()
            appliances = self.get_request(self.regional_base_url, 
                '/appliance/api/v2/appliances?includeMetadata=true', self.get_headers_frigidaire("GET", include_bearer_token=True))

        for raw_appliance in appliances:
            if raw_appliance['applianceId'] == appliance.appliance_id:
                return raw_appliance['properties']['reported']
        raise FrigidaireException(f"Appliance {appliance.nickname} not found in list of appliances")

    def execute_action(self, appliance: Appliance, action: List[Component]) -> None:
        """
        Executes any defined action on a given appliance
        Will authenticate if the request fails
        :param appliance: The appliance to perform the action on
        :param action: The action to be performed
        :return:
        """

        for component in action:
            data = {
                component.name: component.value
            }

            try:
                self.put_request(self.regional_base_url, 
                    f'/appliance/api/v2/appliances/{appliance.appliance_id}/command',
                    self.get_headers_frigidaire("PUT", include_bearer_token=True), data)
            except FrigidaireException:
                self.re_authenticate()
                self.put_request(self.regional_base_url, 
                    f'/appliance/api/v2/appliances/{appliance.appliance_id}/command',
                    self.get_headers_frigidaire("PUT", include_bearer_token=True), data)

    @staticmethod
    def parse_response(response: Response) -> Dict:
        """
        Parses a response from the Frigidaire API
        :param response: The raw response from the requests lib
        :return: The data in the response, if the response was successful and there is data present
        """
        if response.status_code != 200:
            raise FrigidaireException(f'Request failed with status {response.status_code}: {response.content}')

        try:
            if response.headers.get('Content-Encoding') == 'gzip':
                # Hack: Sometimes the server indicates "Content-Encoding: gzip" but does not send gzipped data
                try:
                    data = gzip.decompress(response.content)
                    response_dict = json.loads(data.decode("utf-8"))
                except gzip.BadGzipFile:
                    logging.debug("Bad gzipped payload-- attempting to parse as plaintext")
                    response_dict = response.json()
            else:
                response_dict = response.json()
        except Exception as e:
            logging.error(e)
            raise FrigidaireException(f'Received an unexpected response:\n{response.content}')

        return response_dict

    def handle_request_exception(self, e: Exception, method: str, fullpath: str, headers: Dict[str, str], payload: str):
        logging.warning(e)
        error_str = f'Error processing request:\n{method} {fullpath}\nheaders={headers}\npayload={payload}\n'
        'This may be safely ignored when used to test for a good connection in the authentication flow'
        logging.warning(error_str)
        raise FrigidaireException(error_str)

    def get_request(self, url: str, path: str, headers: Dict[str, str]) -> Union[Dict, List]:
        """
        Makes a get request to the Frigidaire API and parses the result
        :parm url: Base URL for the request (no slashes)
        :param path: The path to the resource, including query params
        :param headers: Headers to include in the request
        :return: The contents of 'data' in the resulting json
        """
        try:
            response = requests.get(f'{url}{path}', headers=headers, verify=False, timeout=self.timeout)
            return self.parse_response(response)
        except Exception as e:
            self.handle_request_exception(e, "GET", f'{url}{path}', headers, "")

    def post_request(self, url: str, path: str, headers: Dict[str, str], data: Dict, form_encoding: bool=False) -> Union[Dict, List]:
        """
        Makes a post request to the Frigidaire API and parses the result
        :parm url: Base URL for the request (no slashes)
        :param path: The path to the resource, including query params
        :param data: The data to include in the body of the request
        :param form_encoding: Whether to form-encode data. If false, encodes as json
        :return: The contents of 'data' in the resulting json
        """
        try:
            encoded_data = urlencode(data) if form_encoding else json.dumps(data)
            response = requests.post(f'{url}{path}', data=encoded_data,
                    headers=headers, verify=False, timeout=self.timeout)
            return self.parse_response(response)
        except Exception as e:
            self.handle_request_exception(e, "POST", f'{url}{path}', headers, encoded_data)

    def put_request(self, url: str, path: str, headers: Dict[str, str], data: Dict):
        """
        Makes a put request to the Frigidaire API and parses the result
        :parm url: Base URL for the request (no slashes)
        :param path: The path to the resource, including query params
        :param data: The data to include in the body of the request
        :return: The contents of 'data' in the resulting json
        """
        try:
            encoded_data = json.dumps(data)
            response = requests.put(f'{url}{path}', data=encoded_data,
                    headers=headers, verify=False, timeout=self.timeout)
        except Exception as e:
            self.handle_request_exception(e, "PUT", f'{url}{path}', headers, encoded_data)
