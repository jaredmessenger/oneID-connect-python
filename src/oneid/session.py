from __future__ import unicode_literals

import os
import yaml
import json
from requests import request
from codecs import open

from cryptography.exceptions import InvalidSignature

from . import service, utils, exceptions

REQUIRED_JWT_HEADER_ELEMENTS = {
    'typ': 'JWT',
    'alg': 'ES256',
}


class SessionBase(object):
    """
    Abstract Session Class

    :ivar identity_credentials: oneID identity :class:`~oneid.keychain.Credentials`
    :ivar application_credentials: unique app credentials :class:`~oneid.keychain.Credentials`
    :ivar project_credentials: unique project credentials :class:`~oneid.keychain.Credentials`
    :ivar oneid_credentials: oneID project credentials :class:`~oneid.keychain.Credentials`
    """
    def __init__(self, identity_credentials=None, application_credentials=None,
                 project_credentials=None, oneid_credentials=None, config=None):
        """

        :param identity_credentials: :py:class:`~oneid.keychain.Credentials`
        :param application_credentials: :py:class:`~oneid.keychain.Credentials`
        :param project_credentials: :py:class:`~oneid.keychain.ProjectCredentials`
        :param oneid_credentials: :py:class:`~oneid.keychain.Credentials`
        :param config: Dictionary or configuration keyword arguments
        :return:
        """
        self.identity_credentials = identity_credentials
        self.app_credentials = application_credentials
        self.project_credentials = project_credentials
        self.oneid_credentials = oneid_credentials

    def _load_config(self, config_file):
        """
        Load configuration from file
        :return: dict()
        """
        # Load params from configuration file
        with open(config_file, mode='r', encoding='utf-8') as config:
            params = yaml.safe_load(config)
            return params

    def _create_services(self, methods, **kwargs):
        """
        Populate session variables and create methods from args

        :return: None
        """
        service_creator = service.ServiceCreator()

        for method in methods:
            if method != 'GLOBAL':
                setattr(self, method,
                        service_creator.create_service_class(method,
                                                             methods[method],
                                                             self,
                                                             **kwargs)
                        )

    def create_jwt_payload(self, **kwargs):
        """
        Create a generic JWT Payload

        :param claims: JWT Claims Dict()
        :return: JWT payload (*no signature)
        """
        alg = json.dumps(REQUIRED_JWT_HEADER_ELEMENTS)
        alg_b64 = utils.to_string(utils.base64url_encode(utils.to_bytes(alg)))

        # Required claims
        jti = utils.make_nonce()

        claims = {'jti': jti}
        claims.update(kwargs)

        claims_b64 = utils.to_string(utils.base64url_encode(utils.to_bytes(json.dumps(claims))))

        payload = '{alg_b64}.{claims_b64}'.format(alg_b64=alg_b64,
                                                  claims_b64=claims_b64)

        return payload

    def make_http_request(self, http_method, url, headers=None, body=None):
        """
        Generic HTTP request

        :param headers:
        :param body:
        :return:
        """
        valid_http_methods = ['GET', 'PUT', 'POST', 'DELETE']
        if http_method not in valid_http_methods:
            raise TypeError('HTTP method must be %s' %
                            ', '.join(valid_http_methods))

        req = request(http_method, url, headers=headers, data=body)

        # 403 is Forbidden, raise an error if this occurs
        if req.status_code == 403:
            raise exceptions.InvalidAuthentication()

        return req.content

    def prepare_message(self, *args, **kwargs):
        raise NotImplementedError

    def send_message(self, *args, **kwargs):
        raise NotImplementedError

    def verify_message(self, *args, **kwargs):
        raise NotImplementedError


class DeviceSession(SessionBase):
    def __init__(self, identity_credentials=None, application_credentials=None,
                 project_credentials=None, oneid_credentials=None, config=None):
        super(DeviceSession, self).__init__(identity_credentials,
                                            application_credentials,
                                            project_credentials,
                                            oneid_credentials, config)

    def verify_message(self, message, rekey_credentials=None):
        """
        Verify a message received from the server

        :param message: JSON formatted message with two signatures
        :param rekey_credentials: List of :class:`~oneid.keychain.Credential`
        :return: verified message
        :raises: oneid.exceptions.InvalidAuthentication
        """
        data = json.loads(message)
        if not data.get('payload'):
            raise KeyError('missing payload')
        if not data.get('oneid_signature'):
            raise KeyError('missing oneID Digital Signature')
        if not data.get('project_signature') and not data.get('rekey_signatures'):
            raise KeyError('missing project signature')

        # Verify the signatures
        payload = data['payload'].encode('utf-8')

        oneid_sig = data['oneid_signature']

        project_sig = data.get('project_signature')
        rekey_sigs = data.get('rekey_signatures', list())

        if project_sig:
            self.project_credentials.keypair.verify(payload, project_sig)

        elif len(rekey_sigs) == 3 and len(rekey_credentials) == 3:
            if self._check_rekey_sigs(rekey_sigs, rekey_credentials, payload) != 3:
                raise InvalidSignature('One or more signatures were invalid')
        else:
            raise InvalidSignature('Missing project signature')

        self.oneid_credentials.keypair.verify(payload, oneid_sig)

    def _check_rekey_sigs(self, sigs, credentials, payload):
        valid_sig_count = 0
        # Iterate over all the possible signature/credential permutations
        for sig in sigs:
            for cred in credentials:
                try:
                    cred.keypair.verify(payload, sig)
                except InvalidSignature:
                    pass
                else:
                    valid_sig_count += 1
                    break
        return valid_sig_count

    def prepare_message(self, **kwargs):
        """
        Prepare a message before sending

        :return: JSON with JWT payload and two signatures
        """
        kwargs['iss'] = self.identity_credentials.id
        payload = self.create_jwt_payload(**kwargs)
        identity_sig = utils.to_string(self.identity_credentials.keypair.sign(payload))
        app_sig = utils.to_string(self.app_credentials.keypair.sign(payload))

        return json.dumps({'payload': payload,
                           'id_signature': identity_sig,
                           'app_signature': app_sig})

    def send_message(self, *args, **kwargs):
        raise NotImplementedError


class ServerSession(SessionBase):
    """
    Enable Server to request two-factor Authentication from oneID
    """
    def __init__(self, identity_credentials=None, application_credentials=None,
                 project_credentials=None, oneid_credentials=None, config=None):
        super(ServerSession, self).__init__(identity_credentials,
                                            application_credentials,
                                            project_credentials,
                                            oneid_credentials, config)

        if isinstance(config, dict):
            params = config
        else:
            # Load default
            default_config = os.path.join(os.path.dirname(__file__),
                                          'data', 'oneid_server.yaml')
            params = self._load_config(config if config else default_config)

        self._create_services(params)

    def _create_services(self, params, **kwargs):
        """
        Populate session variables and create methods from
        :return: None
        """
        global_kwargs = params.get('GLOBAL', {})
        if self.project_credentials:
            global_kwargs['project_credentials'] = self.project_credentials

        super(ServerSession, self)._create_services(params, **global_kwargs)

    def service_request(self, http_method, endpoint, body=None):
        """
        Make an API Request

        :param method:
        :param endpoint:
        :param body:
        :return:
        """
        payload = self.create_jwt_payload()

        signature = self.identity_credentials.keypair.sign(payload)

        auth_jwt_header = '{payload}.{signature}'.format(payload=payload,
                                                         signature=signature)

        headers = {
            'Content-Type': 'application/jwt',
            'Authorization': 'Bearer %s' % auth_jwt_header
        }

        response = self.make_http_request(http_method, endpoint, headers=headers,
                                          body=body)

        return response

    def prepare_message(self, *args, **kwargs):
        """
        Build message that has two-factor signatures

        :param kwargs: oneid_response to parse and optionally rekey_credentials.
        :return: Content to be sent to devices
        """
        if self.project_credentials is None:
            raise AttributeError

        oneid_response = kwargs.pop('oneid_response')
        # split the JWT Token
        alg, claims, oneid_sig = oneid_response.split('.')
        payload = '{alg}.{claims}'.format(alg=alg, claims=claims)

        reset_credentials = kwargs.get('rekey_credentials', list())
        if len(reset_credentials) == 3:
            reset_sigs = list()
            for cred in reset_credentials:
                sig = utils.to_string(cred.keypair.sign(payload))
                reset_sigs.append(sig)

            return json.dumps({'payload': payload,
                               'oneid_signature': oneid_sig,
                               'reset_signatures': reset_sigs})

        project_sig = utils.to_string(self.project_credentials.keypair.sign(payload))

        return json.dumps({'payload': payload,
                           'project_signature': project_sig,
                           'oneid_signature': oneid_sig})

    def send_message(self, *args, **kwargs):
        raise NotImplementedError

    def verify_message(self, *args, **kwargs):
        raise NotImplementedError


class AdminSession(SessionBase):
    """
    Admin Users will only interface with oneID service,
    They only need an identity_credentials and oneid_credentials
    to verify responses
    """
    def __init__(self, identity_credentials, application_credentials=None,
                 project_credentials=None, oneid_credentials=None, config=None):
        super(AdminSession, self).__init__(identity_credentials,
                                           application_credentials,
                                           project_credentials,
                                           oneid_credentials, config)

        if isinstance(config, dict):
            params = config
        else:
            default_config = os.path.join(os.path.dirname(__file__),
                                          'data', 'oneid_admin.yaml')
            params = self._load_config(config if config else default_config)

        self._create_services(params)

    def _create_services(self, params, **kwargs):
        """
        Populate session variables and create methods from
        :return: None
        """
        global_kwargs = params.get('GLOBAL', {})
        if self.project_credentials:
            global_kwargs['project_credentials'] = self.project_credentials

        super(AdminSession, self)._create_services(params, **global_kwargs)

    def service_request(self, http_method, endpoint, body=None):
        """
        Make an API Request

        :param method:
        :param endpoint:
        :param body:
        :return:
        """
        payload = self.create_jwt_payload()

        signature = self.identity_credentials.keypair.sign(payload)

        auth_jwt_header = '{payload}.{signature}'.format(payload=payload,
                                                         signature=signature)

        headers = {
            'Content-Type': 'application/jwt',
            'Authorization': 'Bearer %s' % auth_jwt_header
        }

        response = self.make_http_request(http_method, endpoint, headers=headers,
                                          body=body)

        return response

    def prepare_message(self, *args, **kwargs):
        raise NotImplementedError

    def send_message(self, *args, **kwargs):
        raise NotImplementedError

    def verify_message(self, *args, **kwargs):
        raise NotImplementedError
