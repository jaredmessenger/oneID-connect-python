import json
import base64
import unittest

import mock

from oneid import session, service, utils, keychain


# Patch Requests
def mock_request(http_method, url, headers=None, data=None):
    """
    Mock an HTTP GET Request
    :param http_method: GET, PUT, POST, DELETE
    :param url:
    :param headers: Dictionary of additional header params
    :param data: Body/payload
    :return:
    """
    class MockResponse:
        def __init__(self, response, status_code):
            self.content = response
            self.status_code = status_code

    if url == 'https://api.oneid.com/project/test-proj-id/cosign_for_edge_device/edge-device-id':
        # TODO, verify JWT
        if http_method.lower() == 'post':
            return MockResponse('hello world', 200)
        else:
            return MockResponse('Method Not Allowed', 405)

    else:
        return MockResponse('Not Found', 404)


class TestSession(unittest.TestCase):
    id_key_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGS'\
                   'M49AwEHBG0wawIBAQQgbKk/yDq5mmGkhs7b\nLNiCMv25GvwYZNtS5JYUh' \
                   '4OLafKhRANCAAQ0B+TfNujp2TNlw+zufTwzZSv3yU9U\ncbl+Ip5kv8Snp' \
                   'p8ksaAGI+DSL7KCih3DXWr9b3Mwjcx0Uxzyrh0Y40z4\n' \
                   '-----END PRIVATE KEY-----'

    proj_key_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCq' \
                     'GSM49AwEHBG0wawIBAQQgfI4sVem1tP+C8vmR\nZjgvAi2JTPKmDq6xa' \
                     'sysp92WJEyhRANCAAQGFnKI49VPfm09stPFcREzzh0NE8OY\n1s6Sabu' \
                     'TGcRKLevloCXsTD0+RhzqorXdZ63pk3B5ac9Ddd+8PWHpzUoz\n' \
                     '-----END PRIVATE KEY-----\n'

    app_key_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqG' \
                    'SM49AwEHBG0wawIBAQQgLIGoI9j4s6ogppvx\nqf1j8ShoiiDFo2Dndqh' \
                    'aAONXhkqhRANCAAQz7gH1LfLxD+8GmHAVFw1LWI6LK1GL\n2wNYb5NxR4' \
                    'ZHQKg/odM76371cvsaMa/w0WtwZ5b8aNKAUGqS+YO+v6mP\n' \
                    '-----END PRIVATE KEY-----\n'

    def setUp(self):
        mock_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.id_key_bytes)
        self.credentials = keychain.Credentials('me', mock_keypair)

    def test_verify_jwt(self):
        valid_jwt = 'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiBudW' \
                    'xsLCAidGVzdF9jbGFpbSI6ICJ0ZXN0X3ZhbHVlIiwgImp0aSI6ICIwM' \
                    'DEyMDE2LTAxLTEzVDAyOjEzOjIxWlZkeG1JciJ9.WiJ_5yTc29VcWLe' \
                    'MiuLE5eP0QUJop_tJT-QBFA2-9rrqjSy7SZ7ADVDkqmd8ZwWvl7J_wf' \
                    'a3GLeNQNkxIJwhSw'

        service.verify_jwt(valid_jwt, self.credentials.keypair)


class TestDeviceSession(unittest.TestCase):
    def setUp(self):
        mock_id_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.id_key_bytes)
        self.id_credentials = keychain.Credentials('device-id', mock_id_keypair)

        mock_app_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.app_key_bytes)
        self.app_credentials = keychain.Credentials('device-id', mock_app_keypair)

    def test_prepare_payload(self):
        sess = session.DeviceSession(self.id_credentials,
                                     application_credentials=self.app_credentials)
        message = sess.prepare_message()

        self.assertIn('payload', message)
        self.assertIn('app_signature', message)
        self.assertIn('id_signature', message)


class TestAdminSession(unittest.TestCase):
    def setUp(self):
        mock_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.id_key_bytes)
        self.credentials = keychain.Credentials('me', mock_keypair)
        self.custom_config = dict()
        global_config = self.custom_config['GLOBAL'] = dict()
        global_config['base_url'] = 'https://myService'

        test_service = self.custom_config['test_service'] = dict()
        test_method = test_service['test_method'] = dict()
        test_method['endpoint'] = '/my/endpoint'
        test_method['method'] = 'POST'
        test_arguments = test_method['arguments'] = dict()
        test_arguments['my_argument'] = {'location': 'jwt',
                                         'required': True}

    def test_admin_session_config(self):
        sess = session.AdminSession(self.credentials,
                                    config=self.custom_config)
        self.assertIsInstance(sess.test_service, service.BaseService)
        self.assertEqual(sess.test_service.__class__.__name__, 'test_service')

    def test_admin_session_missing_arg(self):
        sess = session.AdminSession(self.credentials,
                                    config=self.custom_config)
        self.assertRaises(TypeError, sess.test_service.test_method)

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_admin_session_service_request(self, mock_request):
        """
        Revoke a device
        :return:
        """
        sess = session.AdminSession(self.credentials,
                                    config=self.custom_config)
        response = sess.test_service.test_method(my_argument='Hello World')
        self.assertEqual(response, 'Not Found')













