import os
import base64
import unittest

from oneid import keychain


class TestKeychain(unittest.TestCase):
    BASE_PATH = os.path.dirname(__file__)
    x509_PATH = os.path.join(BASE_PATH, 'x509')

    def test_load_pem_path(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        keychain.Token.from_secret_pem(path=pem_path)

    def test_load_pem_bytes(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        pem_data = open(pem_path)
        keychain.Token.from_secret_pem(key_bytes=pem_data.read())

    def test_load_der_bytes(self):
        der_path = os.path.join(self.x509_PATH, 'ec_sha256.der')
        der_data = open(der_path)
        keychain.Token.from_secret_der(der_data.read())

    def test_export_pem(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        pem_bytes = open(pem_path).read()
        token = keychain.Token.from_secret_pem(key_bytes=pem_bytes)
        self.assertEqual(pem_bytes, token.secret_as_pem)

    def test_export_der_b64(self):
        der_path = os.path.join(self.x509_PATH, 'ec_sha256.der')
        der_bytes = open(der_path).read()
        token = keychain.Token.from_secret_der(der_bytes)
        b64 = base64.b64encode(der_bytes)
        self.assertEqual(b64, token.secret_as_der)

    def test_sign_verify(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        pem_bytes = open(pem_path).read()
        token = keychain.Token.from_secret_pem(key_bytes=pem_bytes)

        signature = token.sign(b'MESSAGE')
        token.verify(b'MESSAGE', signature)

    def test_export_pub_b64(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        pem_bytes = open(pem_path).read()
        token = keychain.Token.from_secret_pem(key_bytes=pem_bytes)
        pub_b64 = b'NAfk3zbo6dkzZcPs7n08M2Ur98lPVHG5fiKeZL_Ep6afJLGgBiPg0i-ygoodw11q_W9zMI3MdFMc8q4dGONM-A'
        self.assertEqual(pub_b64, token.public_key_b64)

