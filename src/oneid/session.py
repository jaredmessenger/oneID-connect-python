import os
import yaml
from requests import request
import json

from . import service, utils, exceptions

REQUIRED_JWT_HEADER_ELEMENTS = {
    'typ': 'JWT',
    'alg': 'ES256',
}


class Session(object):
    """
    Configuration and Credentials in a single easy-to-use object
    """
    def __init__(self, keychain=None):
        """
        Create a new Session object.

        :param keychain: :class:`oneid.keychain.Token` instance
        """
        # TODO: Load default credentials if keychain not provided
        self.keychain = keychain

        params = self._load_config()
        self._create_services(params)

    def _load_config(self):
        """
        Load configuration from file
        :return: dict()
        """
        # Load params from configuration file
        config_file = os.path.join(os.path.dirname(__file__), 'data', 'oneid.yaml')
        with open(config_file, mode='r') as config:
            params = yaml.safe_load(config)
            return params

    def _create_services(self, params):
        """
        Populate session variables and create methods from
        :return: None
        """
        service_creator = service.ServiceCreator()

        # iterate over dynamic commands
        global_kwargs = params.get('GLOBAL')
        for cmd in params:
            if cmd != 'GLOBAL':
                setattr(self, cmd, service_creator.create_service_class(cmd, params[cmd], self, **global_kwargs))

    def build_jwt(self, **kwargs):
        """
        Make a jwt with the default parameters

        :param kwargs: Additional claims by the user.
        :return: JWT with default algorithm.
        """
        alg_b64 = utils.base64url_encode(json.dumps(REQUIRED_JWT_HEADER_ELEMENTS))

        # Required claims
        jti = utils.make_nonce()
        iss = self.keychain.identity

        claims = {'jti': jti, 'iss': iss}
        claims.update(kwargs)

        claims_serialized = json.dumps(claims)
        claims_b64 = utils.base64url_encode(claims_serialized)

        payload = '{alg_b64}.{claims_b64}'.format(alg_b64=alg_b64,
                                                  claims_b64=claims_b64)

        signature = self.keychain.sign(payload)

        return '{payload}.{signature}'.format(payload=payload, signature=signature)

    def make_http_request(self, url, http_method, body=None):
        """
        Make a standard HTTP request

        :param url: URL to resource
        :param http_method: GET, PUT, POST, DELETE
        :param body: Optional http body argument
        :return: HTTP Content
        :raises: :class:`oneid.exceptions.InvalidAuthentication`
        """
        valid_http_methods = ['GET', 'PUT', 'POST', 'DELETE']
        if http_method not in valid_http_methods:
            raise ValueError('http method must be %s' %
                             ', '.join(valid_http_methods))

        auth_jwt_header = self.build_jwt()

        headers = {
            'Content-Type': 'application/jwt',
            'Authorization': 'Bearer %s' % auth_jwt_header
        }

        # Will raise exceptions.ConnectionError or HTTPError
        req = request(http_method, url, headers=headers, data=body)

        if req.status_code == 403:
            raise exceptions.InvalidAuthentication()

        return req.content


    def get_service_model(self, service_name):
        """
        Get :class:`oneid.service.Service` object

        :param service_name:
        :return: :class:`oneid.service.Service
        """
        raise NotImplementedError