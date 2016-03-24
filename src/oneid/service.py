# -*- coding: utf-8 -*-

"""
Provides useful functions for interacting with the oneID API, including creation of
keys, JWTs, etc.
"""
from __future__ import unicode_literals

import os
import json
import base64
import re
import time
import logging

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization \
    import Encoding, PrivateFormat, NoEncryption

from .keychain import Keypair
from . import utils

logger = logging.getLogger(__name__)


AUTHENTICATION_ENDPOINT = 'http://developer-portal.oneid.com/api/{project}/authenticate'

B64_URLSAFE_RE = '[0-9a-zA-Z-_]+'
JWT_RE = r'^{b64}\.{b64}\.{b64}$'.format(b64=B64_URLSAFE_RE)

REQUIRED_JWT_HEADER_ELEMENTS = {
    'typ': 'JWT',
    'alg': 'ES256',
}
TOKEN_EXPIRATION_TIME_SEC = (1*60*60)  # one hour
TOKEN_NOT_BEFORE_LEEWAY_SEC = (2*60)   # two minutes
TOKEN_EXPIRATION_LEEWAY_SEC = (0)      # not really needed


class ServiceCreator(object):
    """
    Read yaml file and add methods dynamically from file
    Created by Session
    """
    def create_service_class(self, service_name, service_model, session, **kwargs):
        """
        Service Model is either user, server or edge_device
        """
        class_attrs = self._create_methods(service_model, **kwargs)
        cls = type(str(service_name), (BaseService,), class_attrs)

        return cls(session, kwargs.get('project_credentials'))

    def _create_methods(self, service_model, **kwargs):
        """
        :param service_model:
        :return: Dictionary of class attributes
        """
        base_url = kwargs.get('base_url', '')

        methods = dict()
        for method_name, method_values in service_model.items():
            required_jwt = list()
            all_jwt = list()
            for arg_name, arg_properties in method_values['arguments'].items():
                if arg_properties['location'] == 'jwt':
                    all_jwt.append(arg_name)
                    if arg_properties['required'] is True:
                        required_jwt.append(arg_name)

            absolute_url = '{base}{endpoint}'.format(base=base_url,
                                                     endpoint=method_values['endpoint'])

            methods[method_name] = self._create_api_method(method_name,
                                                           absolute_url,
                                                           method_values['method'],
                                                           all_body_args=all_jwt,
                                                           required_body_args=required_jwt,
                                                           )
        return methods

    def _create_api_method(self, name,
                           endpoint, http_method,
                           all_body_args, required_body_args):
        """
        Add methods to session dynamically from yaml file

        :param method_name: method that will be called
        """
        def _api_call(self, *args, **kwargs):
            if kwargs.get('body') is None:
                # if the body isn't specified, check for
                # required body arguments
                for required in required_body_args:
                    if required not in kwargs:
                        raise TypeError('Missing Required Keyword Argument:'
                                        ' %s' % required)
                kwargs.update(body_args=all_body_args)
            return self._make_api_request(endpoint, http_method, **kwargs)

        _api_call.__name__ = str(name)
        return _api_call


class BaseService(object):
    """
    Dynamically loaded by data files.
    """
    def __init__(self, session, project_credentials=None):
        """
        Create a new Service

        :param session: :class:`oneid.session.Session` instance
        """
        self.session = session

        self.project_credentials = None
        if hasattr(self.session, 'project_credentials') and self.session.project_credentials:
            self.project_credentials = self.session.project_credentials

        self.identity = self.session.identity_credentials.id
        self.credentials = self.session.identity_credentials

        if self.project_credentials and self.project_credentials.id:
            self.project_id = self.project_credentials.id

    def _format_url(self, url_template, **kwargs):
        """
        Url from yaml may require formatting

        :Example:

            /project/{project_id}
            >>> /project/abc-123

        :param url_template: url with arguments that need replaced by vars
        :param params: Dictionary lookup to replace url arguments with
        :return: absolute url
        """
        encoded_params = dict()
        url_args = re.findall(r'{(\w+)}', url_template)
        for url_arg in url_args:
            if url_arg in kwargs:
                encoded_params[url_arg] = kwargs[url_arg]
            elif hasattr(self, url_arg):
                # Check if the argument is a class attribute (i.e. project_id)
                encoded_params[url_arg] = getattr(self, url_arg)
            else:
                raise TypeError('Missing URL argument %s' % url_arg)
        return url_template.format(**encoded_params)

    def _make_api_request(self, endpoint, http_method, **kwargs):
        """
        Convenience method to make HTTP requests and handle responses/error codes

        :param endpoint: URL to the resource
        :param http_method: HTTP method, GET, POST, PUT, DELETE
        :param kwargs: Params to pass to the body or url
        """
        # Split the params based on their type (url or jwt)
        url = self._format_url(endpoint, **kwargs)

        if kwargs.get('body_args'):
            additional_claims = dict()
            for body in kwargs.get('body_args'):
                additional_claims[body] = kwargs[body]

            payload = self.session.create_jwt_payload(**additional_claims)
            jwt = '{payload}.{signature}'.format(
                payload=payload,
                signature=utils.to_string(self.credentials.keypair.sign(payload))
            )
            return self.session.service_request(http_method, url, body=jwt)
        else:
            # Replace the entire body with kwargs['body'] (if present)
            return self.session.service_request(http_method, url,
                                                body=kwargs.get('body'))


def create_secret_key(output=None):
    """
    Create a secret key and save it to a secure location

    :param output: Path to save the secret key
    :return: oneid.keychain.Keypair
    """
    secret_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    secret_key_bytes = secret_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    # Save the secret key bytes to a secure file
    if output and os.path.exists(os.path.dirname(output)):
        with open(output, 'wb') as f:
            f.write(secret_key_bytes)

    return Keypair.from_secret_pem(key_bytes=secret_key_bytes)


def create_aes_key():
    """
    Create an AES256 key for symmetric encryption

    :return: Encryption key bytes
    """
    return os.urandom(32)


def encrypt_attr_value(attr_value, aes_key):
    """
    Convenience method to encrypt attribute properties

    :param attr_value: plain text (string or bytes) that you want encrypted
    :param aes_key: symmetric key to encrypt attribute value with
    :return: Dictionary with base64 encoded cipher text and base 64 encoded iv
    """
    iv = os.urandom(16)
    cipher_alg = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher_alg.encryptor()
    encr_value = encryptor.update(utils.to_bytes(attr_value)) + encryptor.finalize()
    encr_value_b64 = base64.b64encode(encr_value + encryptor.tag)
    iv_b64 = base64.b64encode(iv)
    return {'cipher': 'aes', 'mode': 'gcm', 'ts': 128, 'iv': iv_b64, 'ct': encr_value_b64}


def decrypt_attr_value(attr_ct, aes_key):
    """
    Convenience method to decrypt attribute properties

    :param attr_ct: Dictionary with base64 encoded cipher text and base 64 encoded iv
    :param aes_key: symmetric key to decrypt attribute value with
    :return: plaintext bytes
    """
    if not isinstance(attr_ct, dict) or \
            attr_ct.get('cipher', 'aes') != 'aes' or \
            attr_ct.get('mode', 'gcm') != 'gcm':

        raise ValueError('invalid encrypted attribute')

    iv = base64.b64decode(attr_ct['iv'])
    tag_ct = base64.b64decode(attr_ct['ct'])
    ts = attr_ct.get('ts', 64) // 8
    tag = tag_ct[-ts:]
    ct = tag_ct[:-ts]
    cipher_alg = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag, min_tag_length=8),
        backend=default_backend()
    )
    decryptor = cipher_alg.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


def make_jwt(claims, authorized_keypair):
    """
    Convert claims into JWT

    :type claims: Dictionary that will be converted to json
    :param claims: payload data
    :param authorized_key: :py:class:`~oneid.keychain.Keypair` to sign the request
    :return: JWT
    """
    alg = {'alg': 'ES256',
           'typ': 'JWT'}
    alg_serialized = json.dumps(alg)
    alg_b64 = utils.to_string(utils.base64url_encode(alg_serialized))

    claims_serialized = json.dumps(claims) if isinstance(claims, dict) else claims
    claims_b64 = utils.to_string(utils.base64url_encode(claims_serialized))

    payload = '{alg}.{claims}'.format(alg=alg_b64, claims=claims_b64)

    signature = utils.to_string(authorized_keypair.sign(payload))

    return '{payload}.{sig}'.format(payload=payload, sig=signature)


def verify_jwt(jwt, verification_keypair=None):  # TODO: require verification_token
    """
    Convert a JWT back to it's claims, if validated by the :py:class:`~oneid.keychain.Token`

    :param jwt: JWT to verify and convert
    :type jwt: str or bytes
    :param verification_token: :py:class:`~oneid.keychain.Token` to verify the JWT
    :type param: :py:class:`~oneid.keychain.Token`
    """
    jwt = utils.to_string(jwt)
    if not re.match(JWT_RE, jwt):
        logger.debug('Given JWT doesnt match pattern: %s', jwt)
        return False

    try:
        header, payload, signature = [utils.base64url_decode(p) for p in jwt.split('.')]
    except:
        logger.debug('invalid message, error splitting/decoding: %s', jwt, exc_info=True)
        return False

    if not _verify_jwt_header(utils.to_string(header)):
        return False

    message = _verify_jwt_claims(utils.to_string(payload))

    if message is None:
        logger.debug('no message: %s', message)
        return False

    if verification_keypair:
        try:
            verification_keypair.verify(*(jwt.rsplit('.', 1)))
        except:
            logger.debug('invalid signature, header=%s, message=%s', header, message)
            return False

    return message


def _verify_jwt_header(header):
    try:
        header = json.loads(header)
    except ValueError:
        logger.debug('invalid header, not valid json: %s', header)
        return False
    except Exception:  # pragma: no cover
        logger.debug('unknown error verifying header: %s', header, exc_info=True)
        return False

    for key, value in REQUIRED_JWT_HEADER_ELEMENTS.items():
        if header.pop(key, None) != value:
            logger.debug('invalid header, missing or incorrect %s: %s', key, header)
            return False

    if len(header) > 0:
        logger.debug('invalid header, extra elements: %s', header)
        return False

    return True


def _verify_jwt_claims(payload):
    try:
        message = json.loads(payload)
        now = int(time.time())

        if 'exp' in message and (int(message['exp']) + TOKEN_EXPIRATION_LEEWAY_SEC) < now:
            logger.warning('Expired token, exp=%s, now=%s', message['exp'], now)
            return None

        if 'nbf' in message and (int(message['nbf']) - TOKEN_NOT_BEFORE_LEEWAY_SEC) > now:
            logger.warning('Early token, nbf=%s, now=%s', message['nbf'], now)
            return None

        if 'jti' in message and not utils.verify_and_burn_nonce(message['jti']):
            logger.warning('Invalid nonce: %s', message['jti'])
            return None

        return message

    except:
        logger.debug('unknown error verifying payload: %s', payload, exc_info=True)
        return None
