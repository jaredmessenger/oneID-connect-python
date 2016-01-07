import unittest

from oneid import service, keychain


class TestCreateToken(unittest.TestCase):
    def test_token(self):
        token = service.create_secret_key()
        self.assertIsInstance(token, keychain.Token)

