#!/usr/bin/env python

import os
import math
import hmac
import hashlib
import json
import base64
import struct
import urllib2
import re
import time
import logging

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization \
    import Encoding, PrivateFormat, NoEncryption

from keychain import Token
import utils

logger = logging.getLogger(__name__)


AUTHENTICATION_ENDPOINT = 'http://developer-portal.oneid.com/api/{project}/authenticate'


ONEID_TYPES = utils.enum(DEVICE=0, SERVER=1, USER=2)

B64_URLSAFE_RE = '[0-9a-zA-Z-_]+'
JWT_RE = r'^{b64}\.{b64}\.{b64}$'.format(b64=B64_URLSAFE_RE)

REQUIRED_JWT_HEADER_ELEMENTS = {
    'typ': 'JWT',
    'alg': 'ES256',
}
TOKEN_EXPIRATION_TIME_SEC = (1*60*60)  # one hour
TOKEN_NOT_BEFORE_LEEWAY_SEC = (2*60)   # two minutes
TOKEN_EXPIRATION_LEEWAY_SEC = (0)      # not really needed


def create_secret_key(output=None):
    """
    Create a secret key and save it to a secure location

    :param output: Path to save the secret key
    :return: Secret key bytes.
    """
    secret_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    secret_key_bytes = secret_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    # Save the secret key bytes to a secure file
    if output and os.path.exists(os.path.dirname(output)):
        with open(output, 'w') as f:
            f.write(secret_key_bytes)

    return Token.from_secret_pem(key_bytes=secret_key_bytes)


def encrypt_attr_value(attr_value, aes_key):
    """
    Convenience method to encrypt attribute properties

    :param attr_value: plain text that you want encrypted
    :param aes_key: symmetric key to encrypt attribute value with
    :return: Dictionary with base64 encoded cipher text and base 64 encoded iv
    """
    iv = os.urandom(16)
    cipher_alg = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher_alg.encryptor()
    encr_value = encryptor.update(attr_value) + encryptor.finalize()
    encr_value_b64 = base64.b64encode(encr_value + encryptor.tag)
    iv_b64 = base64.b64encode(iv)
    return {'cipher': 'aes', 'mode': 'gcm', 'ts': 128, 'iv': iv_b64, 'ct': encr_value_b64}


def decrypt_attr_value(attr_ct, aes_key):
    """
    Convenience method to decrypt attribute properties

    :param attr_ct: Dictionary with base64 encoded cipher text and base 64 encoded iv
    :param aes_key: symmetric key to decrypt attribute value with
    :return: Dictionary with base64 encoded cipher text and base 64 encoded iv
    """
    if not isinstance(attr_ct, dict) or attr_ct.get('cipher', 'aes') != 'aes' or attr_ct.get('mode', 'gcm') != 'gcm':
        raise ValueError('invalid encrypted attribute')
    iv = base64.b64decode(attr_ct['iv'])
    tag_ct = base64.b64decode(attr_ct['ct'])
    ts = attr_ct.get('ts', 64) // 8
    tag = tag_ct[-ts:]
    ct = tag_ct[:-ts]
    cipher_alg = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag, min_tag_length=8), backend=default_backend())
    decryptor = cipher_alg.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


def make_jwt(claims, authorized_token):
    """
    Convert claims into JWT

    :type claims: Dictionary that will be converted to json
    :param claims: payload data
    :param authorized_token: Token to sign the request
    :return: JWT
    """
    alg = {'alg': 'ES256',
           'typ': 'JWT'}
    alg_serialized = json.dumps(alg)
    alg_b64 = utils.base64url_encode(alg_serialized)

    claims_serialized = json.dumps(claims)
    claims_b64 = utils.base64url_encode(claims_serialized)

    payload = '{alg}.{claims}'.format(alg=alg_b64, claims=claims_b64)

    signature = authorized_token.sign(payload)

    return '{payload}.{sig}'.format(payload=payload, sig=signature)


def verify_jwt(jwt, verification_token=None):  # TODO: require verification_token
    """
    Convert a JWT back to it's claims, if validated by the token

    :param jwt: JWT to verify and convert
    :type jwt: str
    :param verification_token: :py:class:`Token` to verify the JWT
    :type param: :py:class:`Token`
    """
    if not re.match(JWT_RE, jwt):
        logger.debug('Given JWT doesnt match pattern: %s', jwt)
        return False

    try:
        header, payload, signature = [utils.base64url_decode(p) for p in jwt.split('.')]
    except:
        logger.debug('invalid message, error splitting/decoding: %s', jwt, exc_info=True)
        return False

    if not _verify_jwt_header(header.decode('utf-8')):
        return False

    message = _verify_jwt_claims(payload)

    if message is None:
        logger.debug('no message: %s', message)
        return False

    if verification_token and not verification_token.verify(*(jwt.split('.')[:2]), signature=signature):
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


def request_oneid_authentication(jwt, project_id):
    """
    Send a JWT signed by a server, device or user to oneID
    for a two-factor authenticated message

    :param jwt: Standard jwt with a header, claims and signature
        *MUST HAVE SAME PAYLOAD THAT WILL BE SENT TO IoT DEVICE!
    :param project_id: project id
    :return: JSON(payload, oneID Signature)
    :raises: urllib2.HTTPError
    """
    http_request = urllib2.Request(AUTHENTICATION_ENDPOINT.format(project=project_id))
    http_request.add_header('Content-Type', 'application/jwt')

    return urllib2.urlopen(http_request, jwt)


def kdf(derivation_key, label, context='', key_size=128):
    prf_output_size = 256
    num_iterations = int(math.ceil((key_size+0.0)/prf_output_size))

    if num_iterations > (math.pow(2, 32)-1):
        return

    prf_results = ['']
    result = ''
    params = ''
    for i in range(1, num_iterations+1):
        params = "%s%s%s%s%s%s" % (prf_results[i-1],
                                   struct.pack('>I', i),
                                   label, chr(0),
                                   context,
                                   struct.pack('>I', key_size))
        digest = hmac.new(derivation_key, params, digestmod=hashlib.sha256).digest()
        prf_results.append(digest)
        result += digest
        pass
    return result[:key_size/8]
