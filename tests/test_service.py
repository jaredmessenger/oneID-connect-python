import unittest
import mock


from oneid import service, keychain


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


class TestCreateToken(unittest.TestCase):
    def test_token(self):
        kp = service.create_secret_key()
        self.assertIsInstance(kp, keychain.Keypair)

