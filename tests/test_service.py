import unittest

from oneid import service, keychain


class TestBaseService(unittest.TestCase):
    def setUp(self):
        self.service = service.BaseService(None, None)

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
        token = service.create_secret_key()
        self.assertIsInstance(token, keychain.Token)

