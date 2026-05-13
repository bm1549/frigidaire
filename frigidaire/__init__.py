"""Frigidaire 2.0 API client"""

import gzip
import json
import logging
import random
import time
import traceback
from collections.abc import Callable
from enum import Enum
from typing import NoReturn, Optional, TypeVar, cast
from urllib.parse import urlencode

import requests
import urllib3
from requests import Response

from .signature_generator import get_signature

T = TypeVar("T")

# Frigidaire uses a self-signed certificate, which forces us to disable SSL verification
# To keep our logs free of spam, we disable warnings on insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GLOBAL_API_URL = "https://api.ocp.electrolux.one"

FRIGIDAIRE_API_KEY = "3BAfxFtCTdGbJ74udWvSe6ZdPugP8GcKz3nSJVfg"
CLIENT_SECRET = (
    "26SGRupOJaxv4Y1npjBsScjJPuj7f8YTdGxJak3nhAnowCStsBAEzKtrEHsgbqUyh90"
    "KFsoty7xXwMNuLYiSEcLqhGQryBM26i435hncaLqj5AuSvWaGNRTACi7ba5yu"
)
CLIENT_ID = "FrigidaireOneApp"
FRIGIDAIRE_USER_AGENT = "Ktor client"
AUTH_USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 12; sdk_gphone64_x86_64 Build/SE1A.220826.008)"

# Header names whose values are credentials; matched case-insensitively.
_REDACT_HEADERS = frozenset({"authorization", "x-api-key"})

# Top-level JSON keys whose values are credentials in auth-flow request bodies.
_REDACT_PAYLOAD_KEYS = frozenset(
    {"password", "clientSecret", "apiKey", "oauth_token", "idToken", "id_token", "sig", "accessToken"}
)


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: ("<redacted>" if k.lower() in _REDACT_HEADERS else v) for k, v in headers.items()}


def _redact_payload(payload: str) -> str:
    if not payload:
        return payload
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return payload
    if not isinstance(data, dict):
        return payload
    return json.dumps({k: ("<redacted>" if k in _REDACT_PAYLOAD_KEYS else v) for k, v in data.items()})


class FrigidaireException(Exception):
    pass


# Maps known Electrolux internal platform codenames to destination types.
# These codenames appear in applianceData.modelName for newer devices instead
# of the legacy "AC"/"DH" values. Add new entries here as they are confirmed.
_MODEL_MAPPINGS: dict[str, "Destination"]


class Destination(str, Enum):
    AIR_CONDITIONER = "AC"
    DEHUMIDIFIER = "DH"

    @classmethod
    def from_appliance_type(cls, appliance_type: str) -> "Destination":
        """
        Maps known model names to their corresponding destination types.
        Falls back to direct enum lookup for backward compatibility.

        :param appliance_type: The model name from the appliance data
        :return: The appropriate Destination enum value
        :raises ValueError: If the model name is not recognized
        """
        if appliance_type in _MODEL_MAPPINGS:
            return _MODEL_MAPPINGS[appliance_type]
        try:
            return cls(appliance_type)
        except ValueError as e:
            raise ValueError(
                f"'{appliance_type}' is not a recognized model name or destination type. "
                f"Known destinations: {list(cls)}, "
                f"Known models: {list(_MODEL_MAPPINGS.keys())}"
            ) from e


_MODEL_MAPPINGS = {
    "Husky": Destination.DEHUMIDIFIER,  # e.g. FHDD5033W1 (50-pint WiFi dehumidifier)
    "Eagle": Destination.DEHUMIDIFIER,  # e.g. GHDD5035W1 (50-pint Gallery WiFi dehumidifier)
    "Panther": Destination.AIR_CONDITIONER,  # e.g. FHWW105WE1 (window inverter AC)
    "Telica": Destination.AIR_CONDITIONER,  # e.g. GHPH142AA1 (portable inverter AC/heat)
}

# Reported property keys that are unique to each destination type.
# Used to infer destination when the codename is not in _MODEL_MAPPINGS.
_AC_PROPERTY_KEYS = {
    "targetTemperatureC",
    "targetTemperatureF",
    "ambientTemperatureC",
    "ambientTemperatureF",
    "temperatureRepresentation",
}
_DH_PROPERTY_KEYS = {"targetHumidity", "sensorHumidity", "waterBucketLevel"}


class Setting(str, Enum):
    """
    Writeable settings that are known valid names of Components.
    These can be passed to the execute_action() API together with a target value
    to change settings.
    """

    # Common
    FAN_SPEED = "fanSpeedSetting"
    EXECUTE_COMMAND = "executeCommand"
    MODE = "mode"
    SLEEP_MODE = "sleepMode"
    UI_LOCK_MODE = "uiLockMode"
    VERTICAL_SWING = "verticalSwing"

    # AC
    TARGET_TEMPERATURE_C = "targetTemperatureC"
    TARGET_TEMPERATURE_F = "targetTemperatureF"
    TEMPERATURE_REPRESENTATION = "temperatureRepresentation"

    # Humidifier
    CLEAN_AIR_MODE = "cleanAirMode"
    DISPLAY_LIGHT = "displayLight"
    START_TIME = "startTime"
    STOP_TIME = "stopTime"
    TARGET_HUMIDITY = "targetHumidity"


class Detail(str, Enum):
    """
    Readable details that are known to be present in some products.
    """

    # Common
    ALERTS = "alerts"
    APPLIANCE_STATE = "applianceState"
    APPLIANCE_UI_SW_VERSION = "applianceUiSwVersion"
    FAN_SPEED = "fanSpeedSetting"
    FAN_SPEED_STATE = "fanSpeedState"
    FILTER_STATE = "filterState"
    MODE = "mode"
    NETWORK_INTERFACE = "networkInterface"
    UI_LOCK_MODE = "uiLockMode"
    SLEEP_MODE = "sleepMode"
    VERTICAL_SWING = "verticalSwing"

    # AC
    AMBIENT_TEMPERATURE_C = "ambientTemperatureC"
    AMBIENT_TEMPERATURE_F = "ambientTemperatureF"
    TARGET_TEMPERATURE_C = "targetTemperatureC"
    TARGET_TEMPERATURE_F = "targetTemperatureF"
    TEMPERATURE_REPRESENTATION = "temperatureRepresentation"

    # Humidifier
    DISPLAY_LIGHT = "displayLight"
    CLEAN_AIR_MODE = "cleanAirMode"
    SENSOR_HUMIDITY = "sensorHumidity"
    START_TIME = "startTime"
    STOP_TIME = "stopTime"
    TARGET_HUMIDITY = "targetHumidity"
    WATER_BUCKET_LEVEL = "waterBucketLevel"


class Appliance:
    def __init__(self, args: dict):
        self.appliance_id: str = args["applianceId"]
        self.appliance_type: str = args["applianceData"]["modelName"]
        self.nickname: str = args["applianceData"]["applianceName"]
        self.destination = self._resolve_destination(args)

    def _resolve_destination(self, args: dict) -> Optional["Destination"]:
        try:
            return Destination.from_appliance_type(self.appliance_type)
        except ValueError:
            pass

        # Check DH first: humidity/water-bucket keys are DH-exclusive, while the "AC" keys
        # (ambient temperature, temperature representation) are also reported by
        # dehumidifiers that display room temp.
        reported_keys = set(args.get("properties", {}).get("reported", {}).keys())
        if reported_keys & _DH_PROPERTY_KEYS:
            logging.warning(
                f"Unknown appliance type '{self.appliance_type}' for '{self.nickname}' "
                f"({self.appliance_id}) — inferred DEHUMIDIFIER from reported properties. "
                f"Please report this at https://github.com/bm1549/frigidaire/issues"
            )
            return Destination.DEHUMIDIFIER
        if reported_keys & _AC_PROPERTY_KEYS:
            logging.warning(
                f"Unknown appliance type '{self.appliance_type}' for '{self.nickname}' "
                f"({self.appliance_id}) — inferred AIR_CONDITIONER from reported properties. "
                f"Please report this at https://github.com/bm1549/frigidaire/issues"
            )
            return Destination.AIR_CONDITIONER

        logging.warning(
            f"Unrecognized appliance type '{self.appliance_type}' for '{self.nickname}' "
            f"({self.appliance_id}) — skipping. Reported keys: {sorted(reported_keys)}. "
            f"Please report this at https://github.com/bm1549/frigidaire/issues"
        )
        return None


class Component:
    def __init__(self, name: str | Setting, value: int | str):
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


class ApplianceState(str, Enum):
    OFF = "OFF"
    RUNNING = "RUNNING"
    DELAYED_START = "DELAYED_START"


class FilterState(str, Enum):
    BUY = "BUY"
    CHANGE = "CHANGE"
    CLEAN = "CLEAN"
    GOOD = "GOOD"


class Power(str, Enum):
    ON = "ON"
    OFF = "OFF"


class SleepMode(str, Enum):
    ON = 'ON'
    OFF = 'OFF'


class VerticalSwing(str, Enum):
    ON = 'ON'
    OFF = 'OFF'


class Alert(str, Enum):
    BUCKET_FULL = "BUCKET_FULL"
    BUS_HIGH_VOLTAGE = "BUS_HIGH_VOLTAGE"
    COMMUNICATION_FAULT = "COMMUNICATION_FAULT"
    DC_MOTOR_FAULT = "DC_MOTOR_FAULT"
    DC_MOTOR_LOST_SPEED = "DC_MOTOR_LOST_SPEED"
    DRAIN_PAN_FULL = "DRAIN_PAN_FULL"
    INDOOR_DEFROST_THERMISTOR_FAULT = "INDOOR_DEFROST_THERMISTOR_FAULT"
    PM25_SENSOR_FAULT = "PM25_SENSOR_FAULT"
    TUBE_HIGH_TEMPERATURE = "TUBE_HIGH_TEMPERATURE"
    UNKNOWN_STATE_ERROR = "UNKNOWN_STATE_ERROR"


class Mode(str, Enum):
    # Air Conditioner
    OFF = "OFF"
    COOL = "COOL"
    FAN = "FANONLY"
    ECO = "ECO"
    # Dehumidifier
    DRY = "DRY"
    AUTO = "AUTO"
    CONTINUOUS = "CONTINUOUS"
    QUIET = "QUIET"


class FanSpeed(str, Enum):
    # Common
    LOW = "LOW"
    MEDIUM = "MIDDLE"
    HIGH = "HIGH"
    # Air Conditioner
    AUTO = "AUTO"


class Action:
    @classmethod
    def set_power(cls, power: Power) -> list[Component]:
        return [Component(Setting.EXECUTE_COMMAND, power)]

    @classmethod
    def set_mode(cls, mode: Mode) -> list[Component]:
        return [Component(Setting.MODE, mode)]

    @classmethod
    def set_fan_speed(cls, fan_speed: FanSpeed) -> list[Component]:
        return [Component(Setting.FAN_SPEED, fan_speed)]

    @classmethod
    def set_ui_lock_mode(cls, ui_lock_mode: bool) -> list[Component]:
        return [Component(Setting.UI_LOCK_MODE, ui_lock_mode)]

    @classmethod
    def set_vertical_swing(cls, vertical_swing: VerticalSwing) -> list[Component]:
        return [Component(Setting.VERTICAL_SWING, vertical_swing)]

    @classmethod
    def set_sleep_mode(cls, sleep_mode: SleepMode) -> list[Component]:
        return [Component(Setting.SLEEP_MODE, sleep_mode)]

    @classmethod
    def set_stop_time(cls, stop_time: int) -> list[Component]:
        """Stop time in seconds; device snaps to ~30-min increments (min ~1800s, use 0 to clear)."""
        if stop_time < 0:
            raise FrigidaireException("StopTime must be greater than or equal to 0")

        return [Component(Setting.STOP_TIME, stop_time)]

    @classmethod
    def set_start_time(cls, start_time: int) -> list[Component]:
        """Start time in seconds; device snaps to ~30-min increments (min ~1800s, use 0 to clear)."""
        if start_time < 0:
            raise FrigidaireException("StartTime must be greater than or equal to 0")

        return [Component(Setting.START_TIME, start_time)]

    @classmethod
    def set_humidity(cls, humidity: int) -> list[Component]:
        if humidity < 35 or humidity > 85:
            raise FrigidaireException("Humidity must be between 35 and 85 percent, inclusive")

        return [Component(Setting.TARGET_HUMIDITY, humidity)]

    @classmethod
    def set_temperature(cls, temperature: int, temperature_unit: Unit = Unit.FAHRENHEIT) -> list[Component]:
        # Note: Frigidaire sets limits for temperature which could cause this action to fail
        # Temperature ranges are below, inclusive of the endpoints
        #   Fahrenheit: 60-90
        #   Celsius: 16-32
        logging.debug(f"Client setting target to {temperature} {temperature_unit}")
        temperature_unit_setting = (
            Setting.TARGET_TEMPERATURE_F if temperature_unit == Unit.FAHRENHEIT else Setting.TARGET_TEMPERATURE_C
        )

        return [
            Component(Setting.TEMPERATURE_REPRESENTATION, temperature_unit),
            Component(temperature_unit_setting, temperature),
        ]


def _generate_nonce() -> str:
    """
    Generate a one-off random token to preserve the security of encrypted communication
    """
    return f"{str(int(time.time()))}_-{str(random.getrandbits(32))}"


class Frigidaire:
    """
    An API for interfacing with Frigidaire Air Conditioners
    This was reverse-engineered from the Frigidaire 2.0 App
    """

    def __init__(
        self,
        username: str,
        password: str,
        session_key: str | None = None,
        timeout: float | None = None,
        regional_base_url: str | None = None,
        country_code: str | None = "US",
    ):
        """
        Initializes a new instance of the Frigidaire API and authenticates against it
        :param username: The username to log in to Frigidaire. Generally, this is an email
        :param password: The password to log in to Frigidaire
        :param session_key: The previously authenticated session key to connect to Frigidaire. If not specified,
                            authentication is required
        :param timeout: The amount of time in seconds to wait before timing out a request
        :param regional_base_url: Regional base URL for the API user account
                            (e.g., https://api.us.ocp.electrolux.one for U.S. accounts). If not specified,
                            authentication is required
        :param country_code: Country code from which to derive regional base URL. Defaults to "US".
        """
        self.username = username
        self.password = password
        self.session_key: str | None = session_key
        self.timeout: float | None = timeout
        self.regional_base_url = regional_base_url
        self.country_code = country_code

        self.authenticate()

    def get_headers_frigidaire(self, method: str, include_bearer_token: bool) -> dict[str, str]:
        to_return = {
            "x-api-key": FRIGIDAIRE_API_KEY,
            "Authorization": "Bearer"
            if not (self.session_key and include_bearer_token)
            else f"Bearer {self.session_key}",
            "Accept": "application/json",
            "Accept-Charset": "UTF-8",
            "User-Agent": FRIGIDAIRE_USER_AGENT,
        }
        if method.upper() != "GET":
            to_return["Content-Type"] = "application/json"
        return to_return

    @staticmethod
    def get_headers_auth(method: str) -> dict[str, str]:
        to_return = {"User-Agent": AUTH_USER_AGENT, "Accept-Encoding": "gzip", "connection": "close"}
        if method.upper() != "GET":
            to_return["Content-Type"] = "application/x-www-form-urlencoded"
        return to_return

    def test_connection(self) -> None:
        """
        Tests for successful connectivity to the Frigidaire server
        :return:
        """
        self.get_request(
            self.regional_base_url,
            "/one-account-user/api/v1/users/current?countryDetails=true",
            self.get_headers_frigidaire("GET", include_bearer_token=True),
        )

    def authenticate(self) -> None:
        """
        Authenticates with the Frigidaire API

        This will re-authenticate if the session key is deemed invalid

        Will throw an exception if the authentication request fails or returns an unexpected response
        :return:
        """

        if not self.regional_base_url:
            self.session_key = None

        # Remember to include "Context-Brand: frigidaire" in the headers for
        # the "/api/v1/identity-providers" and "/api/v1/users/current" calls
        if self.session_key:
            logging.debug("Authentication requested but session key is present, testing session key")
            try:
                self.test_connection()
                logging.debug("Session key is still valid, doing nothing")
                return None
            except (FrigidaireException, ConnectionError):
                logging.debug("Session key is invalid, re-authenticating")
                self.session_key = None

        data = {"grantType": "client_credentials", "clientId": CLIENT_ID, "clientSecret": CLIENT_SECRET, "scope": ""}
        session_key_response = self._post_dict(
            GLOBAL_API_URL,
            "/one-account-authorization/api/v1/token",
            self.get_headers_frigidaire("POST", include_bearer_token=False),
            data,
        )
        self.session_key = session_key_response["accessToken"]

        identity_providers_response = self._get_list_of_dicts(
            GLOBAL_API_URL,
            f"/one-account-user/api/v1/identity-providers?brand=frigidaire&countryCode={self.country_code}",
            self.get_headers_frigidaire("GET", include_bearer_token=True),
        )
        identity_domain = identity_providers_response[0]["domain"]
        identity_api_key = identity_providers_response[0]["apiKey"]
        self.regional_base_url = identity_providers_response[0]["httpRegionalBaseUrl"]

        data = {
            "apiKey": identity_api_key,
            "format": "json",
            "httpStatusCodes": "false",
            "nonce": _generate_nonce(),
            "sdk": "Android_6.2.1",
            "targetEnv": "mobile",
        }
        get_ids_response = self._post_dict(
            f"https://socialize.{identity_domain}",
            "/socialize.getIDs",
            self.get_headers_auth("POST"),
            data,
            form_encoding=True,
        )

        auth_gmid = get_ids_response["gmid"]
        auth_ucid = get_ids_response["ucid"]

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
            "ucid": auth_ucid,
        }
        login_response = self._post_dict(
            f"https://accounts.{identity_domain}",
            "/accounts.login",
            self.get_headers_auth("POST"),
            data,
            form_encoding=True,
        )

        session_info = login_response.get("sessionInfo")
        if (
            session_info is None
            or session_info.get("sessionToken") is None
            or session_info.get("sessionSecret") is None
        ):
            raise FrigidaireException(f"Failed to authenticate, sessionInfo was not in response: {login_response}")

        auth_session_token = session_info["sessionToken"]
        auth_session_secret = session_info["sessionSecret"]

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
            "ucid": auth_ucid,
        }
        sig = get_signature(auth_session_secret, "POST", f"https://accounts.{identity_domain}/accounts.getJWT", data)
        if sig is None:
            raise FrigidaireException("Failed to compute request signature for accounts.getJWT")
        data["sig"] = sig
        jwt_response = self._post_dict(
            f"https://accounts.{identity_domain}",
            "/accounts.getJWT",
            self.get_headers_auth("POST"),
            data,
            form_encoding=True,
        )

        auth_jwt = jwt_response["id_token"]

        data = {
            "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
            "clientId": CLIENT_ID,
            "idToken": auth_jwt,
            "scope": "",
        }
        frigidaire_auth_response = self._post_dict(
            self.regional_base_url,
            "/one-account-authorization/api/v1/token",
            self.get_headers_frigidaire("POST", include_bearer_token=False),
            data,
        )

        access_token = frigidaire_auth_response.get("accessToken")
        if access_token is None:
            raise FrigidaireException(
                f"Failed to authenticate, accessToken was not in response: {frigidaire_auth_response}"
            )

        logging.debug("Authentication successful, storing new session key")
        self.session_key = access_token

    def re_authenticate(self) -> None:
        """
        Removes the session_key and tries to authenticate again
        :return:
        """
        self.session_key = None
        self.authenticate()

    def _post_dict(
        self, url: str | None, path: str, headers: dict[str, str], data: dict, form_encoding: bool = False
    ) -> dict:
        return cast(dict, self.post_request(url, path, headers, data, form_encoding))

    def _get_list_of_dicts(self, url: str | None, path: str, headers: dict[str, str]) -> list[dict]:
        return cast(list[dict], self.get_request(url, path, headers))

    def _with_reauth(self, fn: Callable[[], T]) -> T:
        """Run fn(); if it fails for a non-cas_3403 reason, re-authenticate and retry once."""
        try:
            return fn()
        except FrigidaireException as e:
            # Re-authenticating on a 429 makes things worse
            if "cas_3403" in traceback.format_exc():
                logging.debug("Rate limited - try again later")
                raise e
            logging.debug("Request failed - attempting to re-authenticate")
            self.re_authenticate()
            return fn()

    def _fetch_raw_appliances(self) -> list[dict]:
        return self._get_list_of_dicts(
            self.regional_base_url,
            "/appliance/api/v2/appliances?includeMetadata=true",
            self.get_headers_frigidaire("GET", include_bearer_token=True),
        )

    def get_appliances(self) -> list[Appliance]:
        """
        Uses the Frigidaire API to fetch the list of appliances
        Will authenticate if the request fails
        :return: The appliances that are associated with the Frigidaire account
        """
        logging.debug("Listing appliances")

        def fetch() -> list[Appliance]:
            return [a for a in (Appliance(raw) for raw in self._fetch_raw_appliances()) if a.destination is not None]

        return self._with_reauth(fetch)

    def get_appliance_details(self, appliance: Appliance) -> dict:
        """
        Uses the Frigidaire API to fetch details for a given appliance
        Will authenticate if the request fails
        :param appliance: The appliance to request from the API
        :return: The details for the passed in appliance
        """
        logging.debug(f"Getting appliance details for appliance {appliance.nickname}")
        raw_appliances = self._with_reauth(self._fetch_raw_appliances)

        for raw_appliance in raw_appliances:
            if raw_appliance["applianceId"] == appliance.appliance_id:
                return raw_appliance["properties"]["reported"]
        raise FrigidaireException(f"Appliance {appliance.nickname} not found in list of appliances")

    def execute_action(self, appliance: Appliance, action: list[Component]) -> None:
        """
        Executes any defined action on a given appliance
        Will authenticate if the request fails
        :param appliance: The appliance to perform the action on
        :param action: The action to be performed
        :return:
        """
        path = f"/appliance/api/v2/appliances/{appliance.appliance_id}/command"
        headers = self.get_headers_frigidaire("PUT", include_bearer_token=True)
        for component in action:
            data = {component.name: component.value}

            def send(data: dict = data) -> None:
                self.put_request(self.regional_base_url, path, headers, data)

            self._with_reauth(send)

    @staticmethod
    def parse_response(response: Response) -> dict:
        """
        Parses a response from the Frigidaire API
        :param response: The raw response from the requests lib
        :return: The data in the response, if the response was successful and there is data present
        """
        if response.status_code != 200:
            raise FrigidaireException(f"Request failed with status {response.status_code}: {response.content!r}")

        try:
            if response.headers.get("Content-Encoding") == "gzip":
                # Hack: Often, the server indicates "Content-Encoding: gzip" but does not send gzipped data
                try:
                    data = gzip.decompress(response.content)
                    response_dict = json.loads(data.decode("utf-8"))
                except gzip.BadGzipFile:
                    response_dict = response.json()
            elif response.content == b"":
                # The server says it was JSON, but it was not
                response_dict = {}
            else:
                response_dict = response.json()
        except Exception as e:
            logging.error(e)
            raise FrigidaireException(f"Received an unexpected response:\n{response.content!r}") from e

        return response_dict

    @staticmethod
    def handle_request_exception(
        e: Exception, method: str, fullpath: str, headers: dict[str, str], payload: str
    ) -> NoReturn:
        # Don't log `e` directly: parse_response wraps response bodies into the
        # exception message, and auth-endpoint bodies contain tokens. Callers
        # who need it can inspect __cause__ on the raised exception.
        safe_headers = _redact_headers(headers)
        safe_payload = _redact_payload(payload)
        error_str = (
            f"Error processing request ({type(e).__name__}):\n"
            f"{method} {fullpath}\nheaders={safe_headers}\npayload={safe_payload}\n"
        )
        logging.warning(error_str)
        raise FrigidaireException(error_str) from e

    def get_request(self, url: str | None, path: str, headers: dict[str, str]) -> dict | list:
        """
        Makes a get request to the Frigidaire API and parses the result
        :param url: Base URL for the request (no slashes)
        :param path: The path to the resource, including query params
        :param headers: Headers to include in the request
        :return: The contents of 'data' in the resulting json
        """
        try:
            response = requests.get(f"{url}{path}", headers=headers, verify=False, timeout=self.timeout)
            return self.parse_response(response)
        except Exception as e:
            self.handle_request_exception(e, "GET", f"{url}{path}", headers, "")

    def post_request(
        self, url: str | None, path: str, headers: dict[str, str], data: dict, form_encoding: bool = False
    ) -> dict | list:
        """
        Makes a post request to the Frigidaire API and parses the result
        :param url: Base URL for the request (no slashes)
        :param path: The path to the resource, including query params
        :param headers: Headers to include in the request
        :param data: The data to include in the body of the request
        :param form_encoding: Whether to form-encode data. If false, encodes as json
        :return: The contents of 'data' in the resulting json
        """
        try:
            encoded_data = urlencode(data) if form_encoding else json.dumps(data)
            response = requests.post(
                f"{url}{path}", data=encoded_data, headers=headers, verify=False, timeout=self.timeout
            )
            return self.parse_response(response)
        except Exception as e:
            self.handle_request_exception(e, "POST", f"{url}{path}", headers, json.dumps(data))

    def put_request(self, url: str | None, path: str, headers: dict[str, str], data: dict) -> dict | list:
        """
        Makes a put request to the Frigidaire API and parses the result
        :param url: Base URL for the request (no slashes)
        :param headers: Headers to include in the request
        :param path: The path to the resource, including query params
        :param data: The data to include in the body of the request
        :return: The contents of 'data' in the resulting json
        """
        encoded_data = json.dumps(data)
        try:
            response = requests.put(
                f"{url}{path}", data=encoded_data, headers=headers, verify=False, timeout=self.timeout
            )
            return self.parse_response(response)
        except Exception as e:
            self.handle_request_exception(e, "PUT", f"{url}{path}", headers, encoded_data)


# ---- Auto-enable write rate limiting (safe no-op if already enabled) ----
try:
    from .rl_autowrap import enable_autowrap as _frigidaire_enable_autowrap

    _frigidaire_enable_autowrap()
except Exception:
    # Don't fail imports if autowrap can't be enabled
    pass
# -------------------------------------------------------------------------
