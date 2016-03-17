import os
import unittest

from oneid import keychain


class TestKeychain(unittest.TestCase):
    BASE_PATH = os.path.dirname(__file__)
    x509_PATH = os.path.join(BASE_PATH, 'x509')

    def test_load_pem_path(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        keychain.Keypair.from_secret_pem(path=pem_path)

    def test_load_pem_path_pkcs8(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_pkcs8_private_key.pem')
        keychain.Keypair.from_secret_pem(path=pem_path)

    def test_load_pem_bytes(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        with open(pem_path, 'rb') as f:
            pem_data = f.read()
            keychain.Keypair.from_secret_pem(key_bytes=pem_data)

    def test_load_pem_bytes_pkcs8(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_pkcs8_private_key.pem')
        with open(pem_path, 'rb') as f:
            pem_data = f.read()
            keychain.Keypair.from_secret_pem(key_bytes=pem_data)

    def test_load_pem_public_path(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_public_key.pem')
        keychain.Keypair.from_public_pem(path=pem_path)

    def test_load_public_pem_bytes(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_public_key.pem')
        with open(pem_path, 'rb') as f:
            pem_data = f.read()
            keychain.Keypair.from_public_pem(key_bytes=pem_data)

    def test_load_der_bytes(self):
        der_path = os.path.join(self.x509_PATH, 'ec_sha256.der')
        with open(der_path, 'rb') as f:
            der_data = f.read()
            keychain.Keypair.from_secret_der(der_data)

    def test_export_pem(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        with open(pem_path, 'rb') as f:
            pem_bytes = f.read()
            token = keychain.Keypair.from_secret_pem(key_bytes=pem_bytes)
            self.assertEqual(pem_bytes, token.secret_as_pem)

    def test_export_der(self):
        der_path = os.path.join(self.x509_PATH, 'ec_sha256.der')
        with open(der_path, 'rb') as f:
            der_bytes = f.read()
            token = keychain.Keypair.from_secret_der(der_bytes)
            self.assertEqual(der_bytes, token.secret_as_der)

    def test_sign_verify(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        with open(pem_path, 'rb') as f:
            pem_bytes = f.read()
            token = keychain.Keypair.from_secret_pem(key_bytes=pem_bytes)

            signature = token.sign(b'MESSAGE')
            token.verify(b'MESSAGE', signature)
