"""Frigidaire 2.0 API client"""

from __future__ import annotations

import gzip
import json
import logging
import random
import threading
import time
from collections.abc import Callable
from typing import NoReturn, TypeVar, cast
from urllib.parse import urlencode

import requests
import urllib3
from requests import Response

from .exceptions import AuthenticationError, FrigidaireException, SessionCapError
from .model import (
    Action,
    Alert,
    Appliance,
    ApplianceState,
    CaseInsensitiveEnum,
    Component,
    ConnectionState,
    Destination,
    Detail,
    DisplayLight,
    FanSpeed,
    FilterState,
    Mode,
    Power,
    Setting,
    SleepMode,
    Unit,
    VerticalSwing,
)
from .rate_limit import RateLimiter, wrap_session_request
from .session_store import JsonFileSessionStore, SessionStore
from .signature_generator import get_signature

__all__ = [
    "Action",
    "Alert",
    "Appliance",
    "ApplianceState",
    "AuthenticationError",
    "CaseInsensitiveEnum",
    "Component",
    "ConnectionState",
    "Destination",
    "Detail",
    "DisplayLight",
    "FanSpeed",
    "FilterState",
    "Frigidaire",
    "FrigidaireException",
    "JsonFileSessionStore",
    "Mode",
    "Power",
    "SessionCapError",
    "SessionStore",
    "Setting",
    "SleepMode",
    "Unit",
    "VerticalSwing",
]

T = TypeVar("T")

_LOGGER = logging.getLogger(__name__)

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

SESSION_CAP_ERROR_CODE = "cas_3403"

# Limiters are keyed by account so multiple Frigidaire instances for the same
# account share spacing — without this, a config-flow re-validation that runs
# alongside a live entry would compete and trip cas_3403.
_SCOPED_LIMITERS: dict[str, RateLimiter] = {}

# Re-authentication is serialised per account for the same reason the limiter is
# shared: when several threads fail at once, only the first should mint a new
# session; the rest wait and reuse it.
_SCOPED_REAUTH_LOCKS: dict[str, threading.Lock] = {}

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


def _generate_nonce() -> str:
    """
    Generate a one-off random token to preserve the security of encrypted communication
    """
    return f"{str(int(time.time()))}_-{str(random.getrandbits(32))}"


class Frigidaire:
    """
    An API for interfacing with Frigidaire air conditioners and dehumidifiers.
    This was reverse-engineered from the Frigidaire 2.0 App.
    """

    def __init__(
        self,
        username: str,
        password: str,
        *,
        session_key: str | None = None,
        regional_base_url: str | None = None,
        session_store: SessionStore | None = None,
        timeout: float | None = 15.0,
        country_code: str = "US",
        rate_limit_min_interval: float = 1.25,
        rate_limit_jitter: float = 0.25,
        rate_limit_methods: frozenset[str] | set[str] | None = None,
        rate_limit_scope_key: str | None = None,
        max_retries_on_429: int = 4,
        max_retry_after: float = 60.0,
        session_max_retries: int = 2,
        session_retry_backoff: float = 0.0,
    ):
        """
        Initializes a new instance of the Frigidaire API and authenticates against it
        :param username: The username to log in to Frigidaire. Generally, this is an email
        :param password: The password to log in to Frigidaire
        :param session_key: A previously authenticated session key. Overrides the session store.
        :param regional_base_url: Regional base URL for the API user account
                            (e.g., https://api.us.ocp.electrolux.one for U.S. accounts).
        :param session_store: Where to load the session from and persist it to. The store always
                            ends up holding the session the client is using, so a still-valid
                            token survives restarts instead of lingering server-side until
                            Electrolux's active-session cap (cas_3403) locks the account.
        :param timeout: Per-request HTTP timeout in seconds (default 15.0). None disables the default.
        :param country_code: Country code from which to derive regional base URL. Defaults to "US".
        :param rate_limit_min_interval: Minimum seconds between mutating requests (default 1.25).
        :param rate_limit_jitter: Random jitter added to spacing to smooth bursts (default 0.25).
        :param rate_limit_methods: HTTP methods to throttle (default POST/PUT/PATCH/DELETE).
        :param rate_limit_scope_key: Key for sharing a limiter across instances (default: username).
        :param max_retries_on_429: Max retries on 429/423 before giving up (default 4).
        :param max_retry_after: Cap on the server's Retry-After header in seconds (default 60.0).
        :param session_max_retries: How many times to re-run a failed operation before giving up
                            (default 2): the first extra attempt retries on the existing session,
                            the last re-authenticates first. The session cap (cas_3403) is never
                            retried. 0 disables session retries entirely.
        :param session_retry_backoff: Seconds to sleep before each session retry, scaled by attempt
                            number (default 0.0 = no delay).
        """
        self.username = username
        self.password = password
        self.country_code = country_code
        self._session_store = session_store
        self._session_max_retries = session_max_retries
        self._session_retry_backoff = session_retry_backoff

        if session_key is None and session_store is not None:
            session_key, regional_base_url = session_store.load()
        self.session_key: str | None = session_key
        self.regional_base_url = regional_base_url

        self._session = requests.Session()
        scope = rate_limit_scope_key or username
        limiter = _SCOPED_LIMITERS.setdefault(scope, RateLimiter(rate_limit_min_interval, rate_limit_jitter))
        self._reauth_lock = _SCOPED_REAUTH_LOCKS.setdefault(scope, threading.Lock())
        self._session.request = wrap_session_request(  # type: ignore[method-assign]
            self._session.request,
            limiter,
            rate_limit_methods,
            max_retry_after,
            max_retries_on_429,
            default_timeout=timeout,
        )

        self.authenticate()

    # --- authentication ---

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

    def _test_connection(self) -> None:
        """Raises unless the current session key is accepted by the regional API."""
        self.get_request(
            self.regional_base_url,
            "/one-account-user/api/v1/users/current?countryDetails=true",
            self.get_headers_frigidaire("GET", include_bearer_token=True),
        )

    def authenticate(self) -> None:
        """
        Authenticates with the Frigidaire API.

        Reuses the current session key if the server still accepts it, otherwise runs the full
        login flow. Either way the session store (if any) ends up holding the session in use.

        :raises AuthenticationError: if the credentials are rejected
        :raises FrigidaireException: if any step fails or returns an unexpected response
        """

        if not self.regional_base_url:
            self.session_key = None

        if self.session_key:
            _LOGGER.debug("Authentication requested but session key is present, testing session key")
            try:
                self._test_connection()
                _LOGGER.debug("Session key is still valid, doing nothing")
                self._persist_session()
                return None
            except FrigidaireException:
                _LOGGER.debug("Session key is invalid, re-authenticating")
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
            # The identity provider answers 200 with an errorCode and no sessionInfo when the
            # credentials are wrong. The body is not included: it echoes account details.
            raise AuthenticationError(
                f"Failed to authenticate, sessionInfo was not in response (errorCode={login_response.get('errorCode')})"
            )

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
            raise FrigidaireException("Failed to authenticate, accessToken was not in response")

        _LOGGER.debug("Authentication successful, storing new session key")
        self.session_key = access_token
        self._persist_session()

    def _persist_session(self) -> None:
        """Hand the session in use to the store. Best-effort: a failing store must never sink authentication."""
        if self._session_store is None or self.session_key is None:
            return
        try:
            self._session_store.save(self.session_key, self.regional_base_url)
        except Exception:
            _LOGGER.exception("Session store failed to save the session")

    def _re_authenticate(self) -> None:
        self.session_key = None
        self.authenticate()

    def _with_reauth(self, fn: Callable[[], T]) -> T:
        """Run fn(), retrying on the existing session before falling back to re-authentication.

        Re-authenticating mints a new server-side session, and Electrolux caps active
        sessions (cas_3403). Because tokens stay valid for a long time, an abandoned
        session lingers and these accumulate until the account is locked out. A transient
        failure (timeout, 5xx) does not mean our session is invalid, so we first retry the
        same request on the existing session and only re-authenticate if that also fails.
        cas_3403 is never retried or re-authenticated — that only makes things worse.

        Re-authentication is serialised by a per-account lock: a thread that failed while
        another was minting a new session reuses that session instead of minting its own.
        """
        last_attempt = self._session_max_retries
        for attempt in range(last_attempt + 1):
            key_before = self.session_key
            try:
                return fn()
            except SessionCapError:
                _LOGGER.debug("Session cap hit - try again later")
                raise
            except FrigidaireException:
                if attempt == last_attempt:
                    raise
                if attempt == last_attempt - 1:
                    with self._reauth_lock:
                        if self.session_key == key_before:
                            _LOGGER.debug("Retry failed - attempting to re-authenticate")
                            self._re_authenticate()
                        else:
                            _LOGGER.debug("Another request already re-authenticated - retrying with the new session")
                else:
                    _LOGGER.debug("Request failed - retrying on the existing session")
                if self._session_retry_backoff:
                    time.sleep(self._session_retry_backoff * (attempt + 1))
        raise AssertionError("unreachable")  # pragma: no cover

    # --- appliances ---

    def _fetch_raw_appliances(self) -> list[dict]:
        return self._get_list_of_dicts(
            self.regional_base_url,
            "/appliance/api/v2/appliances?includeMetadata=true",
            self.get_headers_frigidaire("GET", include_bearer_token=True),
        )

    def get_appliances(self) -> list[Appliance]:
        """
        Fetch every appliance on the account, with its current reported state, in one request.
        Will authenticate if the request fails.

        Appliances of a type this library cannot place are skipped with a warning, as are
        malformed records.
        :return: A fresh snapshot of each appliance
        """
        _LOGGER.debug("Listing appliances")

        def fetch() -> list[Appliance]:
            appliances = []
            for record in self._fetch_raw_appliances():
                try:
                    appliance = Appliance(record)
                except (KeyError, TypeError):
                    _LOGGER.warning("Skipping malformed appliance record: %r", record)
                    continue
                if appliance.destination is not None:
                    appliances.append(appliance)
            return appliances

        return self._with_reauth(fetch)

    def execute_action(self, appliance: Appliance, action: list[Component]) -> None:
        """
        Sends each component of an action to an appliance, one request per component.
        Will authenticate if the request fails.
        :param appliance: The appliance to perform the action on
        :param action: The components to send
        """
        path = f"/appliance/api/v2/appliances/{appliance.appliance_id}/command"
        headers = self.get_headers_frigidaire("PUT", include_bearer_token=True)
        for component in action:
            data = {component.name: component.value}

            def send(data: dict = data) -> None:
                self.put_request(self.regional_base_url, path, headers, data)

            self._with_reauth(send)

    # --- commands ---
    #
    # These encode what the appliances actually need, so callers can express intent
    # ("cool at 72") without knowing the protocol's ordering quirks.

    def set_power(self, appliance: Appliance, on: bool) -> None:
        self.execute_action(appliance, Action.set_power(Power.ON if on else Power.OFF))

    def set_mode(self, appliance: Appliance, mode: Mode) -> None:
        """Select an operating mode, powering the appliance on first.

        Air conditioners: power-on is always sent, because the cloud reports the desired state
        rather than the hardware state. After a failed turn-on it keeps saying RUNNING, so
        gating on it would skip the power command on every retry; power is a set, not a
        toggle, so this is harmless on a unit that really is running. A unit that was off
        forgets its setpoint and engaging the mode restores a default, so the remembered
        setpoint is re-sent last. Mode.AUTO is a dehumidifier value that an AC silently
        ignores; its energy-saving mode is ECO.
        """
        if mode is Mode.OFF:
            self.execute_action(appliance, Action.set_mode(Mode.OFF))
            return

        if appliance.destination is Destination.AIR_CONDITIONER:
            if mode is Mode.AUTO:
                mode = Mode.ECO
            was_off = appliance.state is ApplianceState.OFF or appliance.mode is Mode.OFF
            self.set_power(appliance, True)
            self.execute_action(appliance, Action.set_mode(mode))
            target = appliance.target_temperature
            if was_off and target is not None:
                self.set_temperature(appliance, int(target))
            return

        if appliance.state is ApplianceState.OFF:
            self.set_power(appliance, True)
        self.execute_action(appliance, Action.set_mode(mode))

    def set_temperature(self, appliance: Appliance, temperature: int, unit: Unit | None = None) -> None:
        """Set the AC setpoint. Defaults to the unit the appliance reports in."""
        unit = unit or appliance.temperature_unit or Unit.FAHRENHEIT
        self.execute_action(appliance, Action.set_temperature(int(temperature), unit))

    def set_fan_speed(self, appliance: Appliance, fan_speed: FanSpeed) -> None:
        self.execute_action(appliance, Action.set_fan_speed(fan_speed))

    def set_humidity(self, appliance: Appliance, humidity: int) -> None:
        """Set the dehumidifier target. Snaps to 5% steps; the appliance only accepts a target in Dry mode."""
        components = Action.set_humidity(5 * round(humidity / 5))
        self.set_mode(appliance, Mode.DRY)
        self.execute_action(appliance, components)

    def set_sleep_mode(self, appliance: Appliance, on: bool) -> None:
        self.execute_action(appliance, Action.set_sleep_mode(SleepMode.ON if on else SleepMode.OFF))

    def set_vertical_swing(self, appliance: Appliance, on: bool) -> None:
        self.execute_action(appliance, Action.set_vertical_swing(VerticalSwing.ON if on else VerticalSwing.OFF))

    def set_ui_lock(self, appliance: Appliance, on: bool) -> None:
        self.execute_action(appliance, Action.set_ui_lock_mode(on))

    def set_display_light(self, appliance: Appliance, on: bool) -> None:
        self.execute_action(appliance, Action.set_display_light(DisplayLight.ON if on else DisplayLight.OFF))

    def set_clean_air_mode(self, appliance: Appliance, on: bool) -> None:
        self.execute_action(appliance, Action.set_clean_air_mode(on))

    def set_start_time(self, appliance: Appliance, seconds: int) -> None:
        self.execute_action(appliance, Action.set_start_time(seconds))

    def set_stop_time(self, appliance: Appliance, seconds: int) -> None:
        self.execute_action(appliance, Action.set_stop_time(seconds))

    # --- HTTP ---

    def _post_dict(
        self, url: str | None, path: str, headers: dict[str, str], data: dict, form_encoding: bool = False
    ) -> dict:
        return cast(dict, self.post_request(url, path, headers, data, form_encoding))

    def _get_list_of_dicts(self, url: str | None, path: str, headers: dict[str, str]) -> list[dict]:
        return cast("list[dict]", self.get_request(url, path, headers))

    @staticmethod
    def parse_response(response: Response) -> dict:
        """
        Parses a response from the Frigidaire API
        :param response: The raw response from the requests lib
        :return: The data in the response, if the response was successful and there is data present
        """
        if response.status_code != 200:
            # Extract the platform error code (e.g. cas_3403) so callers can classify the
            # failure structurally instead of scanning the traceback string.
            error_code: str | None = None
            try:
                body = response.json()
                if isinstance(body, dict):
                    error_code = body.get("error")
            except Exception:
                pass
            error_class = SessionCapError if error_code == SESSION_CAP_ERROR_CODE else FrigidaireException
            raise error_class(
                f"Request failed with status {response.status_code}: {response.content!r}",
                status_code=response.status_code,
                error_code=error_code,
            )

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
            _LOGGER.error(e)
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
        _LOGGER.warning(error_str)
        # Preserve the exception class and structured fields so callers can still
        # recognise the failure (e.g. the cas_3403 session cap).
        error_class = type(e) if isinstance(e, FrigidaireException) else FrigidaireException
        raise error_class(
            error_str,
            status_code=getattr(e, "status_code", None),
            error_code=getattr(e, "error_code", None),
        ) from e

    def get_request(self, url: str | None, path: str, headers: dict[str, str]) -> dict | list:
        """
        Makes a get request to the Frigidaire API and parses the result
        :param url: Base URL for the request (no slashes)
        :param path: The path to the resource, including query params
        :param headers: Headers to include in the request
        :return: The contents of 'data' in the resulting json
        """
        try:
            response = self._session.get(f"{url}{path}", headers=headers, verify=False)
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
            response = self._session.post(f"{url}{path}", data=encoded_data, headers=headers, verify=False)
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
            response = self._session.put(f"{url}{path}", data=encoded_data, headers=headers, verify=False)
            return self.parse_response(response)
        except Exception as e:
            self.handle_request_exception(e, "PUT", f"{url}{path}", headers, encoded_data)
