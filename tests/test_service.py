import unittest
import mock


from oneid import service, keychain, utils


class TestBaseService(unittest.TestCase):
    def setUp(self):
        mock_credentials = mock.Mock()
        mock_credentials.configure_mock(id='me')
        mock_session = mock.Mock()
        mock_attrs = {'identity_credentials.return_value': mock_credentials}
        mock_session.configure_mock(**mock_attrs)

        self.service = service.BaseService(mock_session, None)

    def test_form_url_params(self):
        url = '/{test_param}/end_test'
        rendered_url = self.service._format_url(url, test_param='swapped')
        self.assertEqual('/swapped/end_test', rendered_url)

    def test_form_url_attr(self):
        url = '/{test_attr}/end_test'
        self.service.test_attr = 'swapped'
        rendered_url = self.service._format_url(url)
        self.assertEqual('/swapped/end_test', rendered_url)

    def test_form_missing_param(self):
        url = '/{test_unknown}/end_test'
        self.assertRaises(TypeError, self.service._format_url, url)

    def test_string_encryption(self):
        key = service.create_aes_key()
        data = 'Hello, Im Data'
        edata = service.encrypt_attr_value(data, key)
        self.assertEqual(utils.to_string(service.decrypt_attr_value(edata, key)), data)

    def test_bytes_encryption(self):
        key = service.create_aes_key()
        data = b'Hello, Im Data'
        edata = service.encrypt_attr_value(data, key)
        self.assertEqual(service.decrypt_attr_value(edata, key), data)

    def test_jwt(self):
        keypair = service.create_secret_key()
        data = {'d': 'Hello, Im Data'}
        jwt = service.make_jwt(data, keypair)
        self.assertEqual(service.verify_jwt(jwt, keypair), data)


class TestCreateToken(unittest.TestCase):
    def test_token(self):
        kp = service.create_secret_key()
        self.assertIsInstance(kp, keychain.Keypair)
