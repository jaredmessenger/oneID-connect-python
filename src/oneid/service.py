#!/usr/bin/env python

import os
import math
import hmac
import hashlib
import json
import base64
import struct
import urllib2

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization \
    import Encoding, PrivateFormat, NoEncryption

from keychain import Token
import utils

AUTHENTICATION_ENDPOINT = 'http://developer-portal.oneid.com/api/{project}/authenticate'


ONEID_TYPES = utils.enum(DEVICE=0, SERVER=1, USER=2)


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