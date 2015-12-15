"""
Token is short for key pair, used to sign and verify signatures

Keys should be kept in a secure storage enclave.
"""
import os

import binascii
import base64

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, \
    EllipticCurvePrivateKey, EllipticCurvePublicNumbers, SECP256R1
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_private_key

from cryptography.hazmat.primitives.asymmetric.utils \
    import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization \
    import Encoding, PublicFormat, PrivateFormat, NoEncryption

import utils


class Token(object):
    """
    oneID Token
    """
    def __init__(self, *args, **kwargs):
        """
        :param args:
        :param kwargs:
        :return:
        """
        self.identity = kwargs.get('identity')

        self._private_key = None
        self._public_key = None

        if kwargs.get('secret_bytes') and \
                isinstance(kwargs['secret_bytes'], EllipticCurvePrivateKey):
            self._load_secret_bytes(kwargs['secret_bytes'])

    def _load_secret_bytes(self, secret_bytes):
        self._private_key = secret_bytes

    @property
    def secret_as_der(self):
        """
        Write out the private key as a DER format

        :return: DER encoded private key
        """
        secret_der = self._private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())

        return base64.b64encode(secret_der)

    @property
    def secret_as_pem(self):
        """
        Write out the private key as a PEM format

        :return: Pem Encoded private key
        """
        return self._private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


    @classmethod
    def from_secret_pem(cls, key_bytes=None, path=None):
        """
        Read a pem file and set it as the private key
        :return: Return new Token instance
        """
        if key_bytes:
            secret_bytes = load_pem_private_key(key_bytes, None, default_backend())
            return cls(secret_bytes=secret_bytes)

        if os.path.exists(path):
            with open(path, 'r') as pem_file:
                secret_bytes = load_pem_private_key(pem_file.read(), None, default_backend())
                return cls(secret_bytes=secret_bytes)


    @classmethod
    def from_secret_der(cls, der_key):
        """
        Read a der_key, convert it a private key
        :param path:
        :return:
        """
        secret_bytes = load_der_private_key(der_key, None, default_backend())
        return cls(secret_bytes=secret_bytes)

    def load_validate(self, x, y):
        """
        load validate key by the curve points
        :param x: long x coordinate of ecc curve
        :param y: long y coordinate of ecc curve
        :return:
        """
        self._public_key = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(default_backend())

    @classmethod
    def from_public_key(cls, public_key):
        """
        Given a URL Safe public key, convert it into a token to validate signatures
        :param public_key: Base64 URL encoded public key
        :return: Token()
        """
        bin_sig = utils.base64url_decode(public_key)
        coordinate_len = len(bin_sig)/2

        bin_x = bin_sig[:coordinate_len]
        bin_y = bin_sig[coordinate_len:]

        x = unpack_bytes(bin_x)
        y = unpack_bytes(bin_y)

        new_token = cls()
        new_token.load_validate(x, y)

        return new_token

    def verify(self, payload, signature):
        """
        Verify that the token signed the data
        :type payload: String
        :param payload: message that was signed and needs verified
        :type signature: Base64 URL Safe
        :param signature: Signature that can verify the senders
         identity and payload
        :return:
        """
        raw_sig = utils.base64url_decode(signature)
        sig_r_bin = raw_sig[:len(raw_sig)/2]
        sig_s_bin = raw_sig[len(raw_sig)/2:]

        sig_r = unpack_bytes(sig_r_bin)
        sig_s = unpack_bytes(sig_s_bin)

        sig = encode_dss_signature(sig_r, sig_s)
        signer = self.public_key.verifier(sig,
                                          ec.ECDSA(hashes.SHA256()))
        signer.update(payload)
        signer.verify()

    def sign(self, payload):
        """
        Sign a payload
        :param payload: String (usually jwt payload)
        :return: URL safe base64 signature
        """
        signer = self._private_key.signer(ec.ECDSA(hashes.SHA256()))

        signer.update(payload)
        signature = signer.finalize()

        r, s = decode_dss_signature(signature)

        b64_signature = utils.base64url_encode('{r}{s}'.format(r=int2bytes(r),
                                                               s=int2bytes(s)))
        return b64_signature

    @property
    def public_key(self):
        """
        If the private key is defined, generate the public key
        :return:
        """
        if self._public_key:
            return self._public_key
        elif self._private_key:
            return self._private_key.public_key()

    @property
    def public_key_b64(self):
        """
        Convert the public key as base64 for sharing
        :return: Base64 Encoded Str()
        """
        public_numbers = self.public_key.public_numbers()

        return utils.base64url_encode('{x}{y}'.format(x=int2bytes(public_numbers.x),
                                                      y=int2bytes(public_numbers.y)))

    @property
    def public_key_der(self):
        """
        DER formatted public key

        :return: Public Key in DER format
        """
        return self.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def save(self, *args, **kwargs):
        """
        Save a key.
        Should be overridden and saved to secure storage
        pr_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pr_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

        :param args:
        :param kwargs:
        :return: Bool Success
        """
        raise NotImplementedError


def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))


def unpack_bytes(stringbytes):
    return int(binascii.hexlify(stringbytes), 16)
