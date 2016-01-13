import os
import base64
import unittest

from oneid import keychain


class TestKeychain(unittest.TestCase):
    BASE_PATH = os.path.dirname(__file__)
    x509_PATH = os.path.join(BASE_PATH, 'x509')

    def test_load_pem_path(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        keychain.Keypair.from_secret_pem(path=pem_path)

    def test_load_pem_bytes(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        pem_data = open(pem_path)
        keychain.Keypair.from_secret_pem(key_bytes=pem_data.read())

    def test_load_der_bytes(self):
        der_path = os.path.join(self.x509_PATH, 'ec_sha256.der')
        der_data = open(der_path)
        keychain.Keypair.from_secret_der(der_data.read())

    def test_export_pem(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        pem_bytes = open(pem_path).read()
        token = keychain.Keypair.from_secret_pem(key_bytes=pem_bytes)
        self.assertEqual(pem_bytes, token.secret_as_pem)

    def test_export_der(self):
        der_path = os.path.join(self.x509_PATH, 'ec_sha256.der')
        der_bytes = open(der_path).read()
        token = keychain.Keypair.from_secret_der(der_bytes)
        self.assertEqual(der_bytes, token.secret_as_der)

    def test_sign_verify(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        pem_bytes = open(pem_path).read()
        token = keychain.Keypair.from_secret_pem(key_bytes=pem_bytes)

        signature = token.sign(b'MESSAGE')
        token.verify(b'MESSAGE', signature)

