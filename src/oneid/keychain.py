
"""
Token is short for key pair, used to sign and verify signatures

Keys should be kept in a secure storage enclave.
"""
import os

import binascii
import base64
import logging

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, \
    load_pem_public_key, load_der_private_key, load_der_public_key

from cryptography.hazmat.primitives.asymmetric.utils \
    import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization \
    import Encoding, PublicFormat, PrivateFormat, NoEncryption

from . import utils

KEYSIZE = 256
KEYSIZE_BYTES = (KEYSIZE // 8)

logger = logging.getLogger(__name__)


class Credentials(object):
    """
    Container for User/Server/Device Encryption Key, Signing Key, Identity


    :ivar identity: UUID of the identity.
    :ivar keypair: :class:`~oneid.keychain.Keypair` instance.
    """
    def __init__(self, uuid, keypair):
        """

        :param identity: uuid of the entity
        :param keypair: :py:class:`~oneid.keychain.Keypair` instance
        """
        self.id = uuid

        if not isinstance(keypair, Keypair):
            raise ValueError('keypair must be a oneid.keychain.Keypair instance')

        self.keypair = keypair


class ProjectCredentials(Credentials):
    def __init__(self, uuid, keypair, encryption_key):
        """
        Adds an ecryption key

        :param uuid: oneID project UUID
        :param keypair: :py:class:`~oneid.keychain.Keypair`
        :param encryption_key: AES key used to encrypt messages
        """
        super(ProjectCredentials, self).__init__(uuid, keypair)
        self._encryption_key = encryption_key

    def encrypt(self, plain_text):
        """
        Encrypt plain text with the project encryption key.

        :param plain_text: String or bytes to encrypt with project encryption key.
        :returns: Dictionary with cipher text and encryption params.
        """
        iv = os.urandom(16)
        cipher_alg = Cipher(
            algorithms.AES(self._encryption_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher_alg.encryptor()
        encr_value = encryptor.update(utils.to_bytes(plain_text)) + encryptor.finalize()
        encr_value_b64 = base64.b64encode(encr_value + encryptor.tag)
        iv_b64 = base64.b64encode(iv)
        return {'cipher': 'aes', 'mode': 'gcm', 'ts': 128, 'iv': iv_b64, 'ct': encr_value_b64}

    def decrypt(self, cipher_text, iv=None, cipher='aes', mode='gcm', tag_size=128):
        """
        Decrypt cipher text that was encrypted with the project encryption key

        :param cipher_text: Encrypted text or dict (as returned by :py:encrypt:)
        :param iv: Base64 encoded initialization vector
        :param mode: [deprecated]
        :param tag_size: [deprecated]
        :returns: plain text
        :return_type: bytes
        """
        if isinstance(cipher_text, dict):
            if 'cipher' not in cipher_text or cipher_text['cipher'].lower() != 'aes' or \
               'mode' not in cipher_text or cipher_text['mode'].lower() != 'gcm' or \
               'ts' not in cipher_text or cipher_text['ts'] != 128:
                raise ValueError('Invalid encryption dict parameters')
            b64_ct = cipher_text.get('ct')
            iv = cipher_text.get('iv')
        else:
            if cipher.lower() != 'aes' or \
               mode.lower() != 'gcm' or \
               tag_size != 128:  # pragma: no cover
                logger.warning('ignoring invalid, deprecated parameters')

            b64_ct = cipher_text

        if iv is None:
            raise ValueError('IV must be specified with using AES and GCM')

        iv = base64.b64decode(iv)
        tag_ct = base64.b64decode(b64_ct)
        ts = 16  # 128 // 8
        tag = tag_ct[-ts:]
        ct = tag_ct[:-ts]
        cipher_alg = Cipher(algorithms.AES(self._encryption_key),
                            modes.GCM(iv, tag, min_tag_length=8),
                            backend=default_backend())
        decryptor = cipher_alg.decryptor()
        return decryptor.update(ct) + decryptor.finalize()


class Keypair(object):
    def __init__(self, *args, **kwargs):
        """
        :param kwargs: Pass secret key bytes
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
        secret_der = self._private_key.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )

        return secret_der

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
        Create a :class:`~oneid.keychain.Keypair` from a PEM-formatted private ECDSA key

        :return: :class:`~oneid.keychain.Keypair` instance
        """
        if key_bytes:
            secret_bytes = load_pem_private_key(utils.to_bytes(key_bytes), None, default_backend())
            return cls(secret_bytes=secret_bytes)

        if os.path.exists(path):
            with open(path, 'rb') as pem_file:
                secret_bytes = load_pem_private_key(pem_file.read(), None, default_backend())
                return cls(secret_bytes=secret_bytes)

    @classmethod
    def from_public_pem(cls, key_bytes=None, path=None):
        """
        Create a :class:`~oneid.keychain.Keypair` from a PEM-formatted public ECDSA key

        Note that this keypair will not be capable of signing, only verifying.

        :return: :class:`~oneid.keychain.Keypair` instance
        """
        ret = None
        public_bytes = None

        if key_bytes:
            public_bytes = utils.to_bytes(key_bytes)
        elif os.path.exists(path):
            with open(path, 'rb') as pem_file:
                public_bytes = pem_file.read()

        if public_bytes:
            ret = cls()
            ret._public_key = load_pem_public_key(public_bytes, default_backend())

        return ret

    @classmethod
    def from_secret_der(cls, der_key):
        """
        Read a der_key, convert it a private key
        :param path: der formatted key
        :return:
        """
        secret_bytes = load_der_private_key(der_key, None, default_backend())
        return cls(secret_bytes=secret_bytes)

    @classmethod
    def from_public_der(cls, public_key):
        """
        Given a DER-format public key, convert it into a token to
        validate signatures
        :param public_key: der formatted key
        :return: :class:`~oneid.keychain.Keypair` instace
        """
        pub = load_der_public_key(public_key, default_backend())

        new_token = cls()
        new_token._public_key = pub

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
        sig_r_bin = raw_sig[:len(raw_sig)//2]
        sig_s_bin = raw_sig[len(raw_sig)//2:]

        sig_r = unpack_bytes(sig_r_bin)
        sig_s = unpack_bytes(sig_s_bin)

        sig = encode_dss_signature(sig_r, sig_s)
        signer = self.public_key.verifier(sig,
                                          ec.ECDSA(hashes.SHA256()))
        signer.update(utils.to_bytes(payload))
        return signer.verify()

    def sign(self, payload):
        """
        Sign a payload
        :param payload: String (usually jwt payload)
        :return: URL safe base64 signature
        """
        signer = self._private_key.signer(ec.ECDSA(hashes.SHA256()))

        signer.update(utils.to_bytes(payload))
        signature = signer.finalize()

        r, s = decode_dss_signature(signature)

        br = int2bytes(r, KEYSIZE_BYTES)
        bs = int2bytes(s, KEYSIZE_BYTES)
        str_sig = br + bs
        b64_signature = utils.base64url_encode(str_sig)
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
    def public_key_der(self):
        """
        DER formatted public key

        :return: Public Key in DER format
        """
        return self.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    @property
    def public_key_pem(self):
        """
        PEM formatted public key

        :return: Public Key in PEM format
        """
        return self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def save(self, *args, **kwargs):
        """
        Save a key.
        Should be overridden and saved to secure storage

        :param args:
        :param kwargs:
        :return: Bool Success
        """
        raise NotImplementedError


def int2bytes(i, numbytes=None):
    hex_string = '%x' % i
    n = numbytes and (numbytes*2) or len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))


def unpack_bytes(stringbytes):
    return int(binascii.hexlify(stringbytes), 16)
