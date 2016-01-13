import unittest

from oneid import service, keychain


class TestCreateToken(unittest.TestCase):
    def test_token(self):
        kp = service.create_secret_key()
        self.assertIsInstance(kp, keychain.Keypair)

