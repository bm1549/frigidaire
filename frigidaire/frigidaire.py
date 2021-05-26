import logging

from requests import Response
from typing import Optional, Dict, Union, List

import json
import requests
import uuid
import time

from frigidaire.appliance import Appliance
from frigidaire.appliance_detail import ApplianceDetail
from frigidaire.action import Component
from frigidaire.exception import FrigidaireAPIException

API_URL = 'https://api.latam.ecp.electrolux.com'

CLIENT_ID = 'e9c4ac73-e94e-4b37-b1fe-b956f568daa0'
USER_AGENT = 'Frigidaire/81 CFNetwork/1206 Darwin/20.1.0'


def parse_response(response: Response) -> Dict:
    """
    Parses a response from the Frigidaire API
    :param response: The raw response from the requests lib
    :return: The data in the response, if the response was successful and there is data present
    """
    if response.status_code != 200:
        raise FrigidaireAPIException(f'Request failed with status {response.status_code}: {response.content}')

    response_dict = response.json()

    if response_dict.get('status') != 'OK' or 'data' not in response_dict:
        raise FrigidaireAPIException(f'Unexpected response from API: {response.content}')

    return response_dict['data']


class Frigidaire:
    """
    An API for interfacing with Frigidaire Air Conditioners
    This was reverse-engineered from the Frigidaire 2.0 App
    """

    def __init__(self, username: str, password: str, session_key: Optional[str] = None):
        """
        Initializes a new instance of the Frigidaire API and authenticates against it
        :param username: The username to login to Frigidaire. Generally, this is an email
        :param password: The password to login to Frigidaire
        :param session_key: The previously authenticated session key to connect to Frigidaire. If not specified,
                            authentication is required
        """
        self.username = username
        self.password = password
        self.device_id: str = str(uuid.uuid4())
        self.session_key: Optional[str] = session_key

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
            except (FrigidaireAPIException, ConnectionError):
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
            raise FrigidaireAPIException(f'Failed to authenticate, sessionKey was not in response: {auth_response}')

        logging.debug('Authentication successful, storing new session key')

        self.session_key: Optional[str] = auth_response['sessionKey']

    def get_appliances(self) -> List[Appliance]:
        """
        Uses the Frigidaire API to fetch the list of appliances.
        Will authenticate if not already authenticated.
        :return: The appliances that are associated with the Frigidaire account
        """
        self.authenticate()

        logging.debug('Listing appliances')
        appliances = self.get_request(
            f'/user-appliance-reg/users/{self.username}/appliances?country=US&includeFields=false'
        )
        return list(map(Appliance, appliances))

    def get_appliance_details(self, appliance: Appliance) -> List[ApplianceDetail]:
        """
        Uses the Frigidaire API to fetch details for a given appliance
        Will authenticate if not already authenticated
        :param appliance: The appliance to request from the API
        :return: The details for the passed in appliance
        """
        self.authenticate()

        details = self.get_request(f'/elux-ms/appliances/latest?{appliance.query_string}&includeSubcomponents=true')
        return list(map(ApplianceDetail, details))

    def execute_action(self, appliance: Appliance, action: List[Component]) -> None:
        """
        Executes any defined action on a given appliance
        Will authenticate if not already authenticated
        :param appliance: The appliance to perform the action on
        :param action: The action to be performed
        :return:
        """
        self.authenticate()

        data = {
            'components': action,
            'timestamp': str(int(time.time())),
            'operationMode': 'EXE',
            'version': 'ad',
            'source': 'RP1',
            'destination': 'AC1',
        }

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
            'user-agent': USER_AGENT,
            'content-type': 'application/json',
            'accept': '*/*',
            'accept-language': 'en-us',
            'authorization': 'Basic dXNlcjpwYXNz',
        }

    def get_request(self, path: str) -> Union[Dict, List]:
        """
        Makes a get request to the Frigidaire API and parses the result
        :param path: The path to the resource, including query params
        :return: The contents of 'data' in the resulting json
        """
        response = requests.get(f'{API_URL}{path}', headers=self.headers, verify=False)
        return parse_response(response)

    def post_request(self, path: str, data: Dict) -> Union[Dict, List]:
        """
        Makes a post request to the Frigidaire API and parses the result
        :param path: The path to the resource, including query params
        :param data: The data to include in the body of the request
        :return: The contents of 'data' in the resulting json
        """
        response = requests.post(f'{API_URL}{path}', data=json.dumps(data), headers=self.headers, verify=False)
        return parse_response(response)
