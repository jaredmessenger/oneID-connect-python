import unittest
import json
import mock

from cryptography.exceptions import InvalidSignature

from oneid import session, service, utils, keychain


# Patch Requests
def mock_request(http_method, url, headers=None, data=None):
    """
    Mock an HTTP GET Request
    :param http_method: GET, PUT, POST, DELETE
    :param url: url that will be overridden
    :param headers: Dictionary of additional header params
    :param data: Body/payload
    :return: :class:`~oneid.test_session.MockResponse`
    """
    class MockResponse:
        def __init__(self, response, status_code):
            self.content = response
            self.status_code = status_code

    if url == 'https://myservice/my/endpoint':
        if http_method.lower() == 'post':
            try:
                jwt_header, jwt_claims, jwt_sig = data.split('.')
            except IndexError:
                return MockResponse('Bad Request', 400)

            try:
                key = keychain.Keypair.from_secret_pem(key_bytes=TestSession.id_key_bytes)
                payload = '{}.{}'.format(jwt_header, jwt_claims)
                key.verify(payload, jwt_sig)
            except InvalidSignature:
                return MockResponse('Forbidden', 403)

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

    oneid_key_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCq' \
                      'GSM49AwEHBG0wawIBAQQgm0PZgUme63i6fC/G\nmNSSsFliywt1eAOoW' \
                      '6Dm/Wz0UrihRANCAATbU7pd0Vg/MYuGOW8E+kpfuo4ov/il\nI9HAi/w' \
                      'HxHqlSxbzagczAUo9kNr4r2w3eTtvf4EuXaC9ZEC9xXCLRCpH\n' \
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

        mock_proj_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.proj_key_bytes)
        self.proj_credentials = keychain.Credentials('proj-id', mock_proj_keypair)

        mock_oneid_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.oneid_key_bytes)
        self.oneid_credentials = keychain.Credentials('oneid-id', mock_oneid_keypair)

    def test_prepare_message(self):
        sess = session.DeviceSession(self.id_credentials,
                                     application_credentials=self.app_credentials)
        message = sess.prepare_message()

        self.assertIn('payload', message)
        self.assertIn('app_signature', message)
        self.assertIn('id_signature', message)

    def test_verify_missing_signature(self):
        message_a = {'payload': 'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ'
                                'pc3MiOiAib25laWQiLCAianRpIjogIjAwMTIwMTYtMDE'
                                'tMjBUMDA6NDU6MzhabjlxSGN5In0=',
                     'oneid_signature': '299qez5eIY1C0qC7GAYDN87LKxkMlQX_r1ESL3'
                                        'eFIbWkoY_hvWOZKrBkynyzetCbWHTZyb1yHp9B'
                                        '_7gUPIwmBQ'}

        message_b = {'payload': 'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ'
                                'pc3MiOiAib25laWQiLCAianRpIjogIjAwMTIwMTYtMDE'
                                'tMjBUMDA6NDU6MzhabjlxSGN5In0=',
                     'project_signature': 'b2z26vlRRpgVXl8UpgAl0x28zdHkrdkcJG'
                                          'JNoC24NdGx5hFPo9PQqx7kW0Qh-4dTgb_B'
                                          'GGHWrwy_6KWMKv8ZkA'}

        sess = session.DeviceSession(self.id_credentials,
                                     application_credentials=self.app_credentials)

        self.assertRaises(KeyError, sess.verify_message, json.dumps(message_a))
        self.assertRaises(KeyError, sess.verify_message, json.dumps(message_b))

    def test_verify_missing_payload(self):
        message = {'project_signature': 'b2z26vlRRpgVXl8UpgAl0x28zdHkrdkcJG'
                                        'JNoC24NdGx5hFPo9PQqx7kW0Qh-4dTgb_B'
                                        'GGHWrwy_6KWMKv8ZkA',
                   'oneid_signature': '299qez5eIY1C0qC7GAYDN87LKxkMlQX_r1ESL3'
                                      'eFIbWkoY_hvWOZKrBkynyzetCbWHTZyb1yHp9B'
                                      '_7gUPIwmBQ'}

        sess = session.DeviceSession(self.id_credentials,
                                     application_credentials=self.app_credentials)

        self.assertRaises(KeyError, sess.verify_message, json.dumps(message))

    def test_verify_project_signature(self):
        message = {'payload': 'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ'
                              'pc3MiOiAib25laWQiLCAianRpIjogIjAwMTIwMTYtMDE'
                              'tMjBUMDA6NDU6MzhabjlxSGN5In0=',
                   'project_signature': 'b2z26vlRRpgVXl8UpgAl0x28zdHkrdkcJG'
                                        'JNoC24NdGx5hFPo9PQqx7kW0Qh-4dTgb_B'
                                        'GGHWrwy_6KWMKv8ZkA',
                   'oneid_signature': '299qez5eIY1C0qC7GAYDN87LKxkMlQX_r1ESL3'
                                      'eFIbWkoY_hvWOZKrBkynyzetCbWHTZyb1yHp9B'
                                      '_7gUPIwmBQ'}
        data = json.dumps(message)
        sess = session.DeviceSession(self.id_credentials,
                                     application_credentials=self.app_credentials,
                                     oneid_credentials=self.oneid_credentials,
                                     project_credentials=self.proj_credentials)
        sess.verify_message(data)


class TestServer(unittest.TestCase):
    def setUp(self):
        mock_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.id_key_bytes)
        self.server_credentials = keychain.Credentials('server', mock_keypair)

        mock_oneid_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.oneid_key_bytes)
        self.oneid_credentials = keychain.Credentials('oneID', mock_oneid_keypair)

        mock_project_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.proj_key_bytes)
        self.project_credentials = keychain.Credentials('proj', mock_project_keypair)

    def test_prepare_message(self):
        oneid_response = 'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3Mi' \
                         'OiAib25lSUQiLCAianRpIjogIjAwMTIwMTYtMDEtMjBUMjE6N' \
                         'TE6MDZabDJ5dHlXIn0=.eEhASqRrKWPhzKVmSmeFZY5tGeTgo' \
                         'nZS45qwnz0_4VJb_qM_kNnQqLp96mPZLUtKHVIeJqA77SqlVx' \
                         'WsOB1J4g'

        sess = session.ServerSession(identity_credentials=self.server_credentials,
                                     oneid_credentials=self.oneid_credentials,
                                     project_credentials=self.project_credentials)

        authenticated_data = sess.prepare_message(oneid_response=oneid_response)

        authenticated_msg = json.loads(authenticated_data)

        self.assertIn('payload', authenticated_msg)
        self.assertIn('project_signature', authenticated_msg)
        self.assertIn('oneid_signature', authenticated_msg)

        self.project_credentials.keypair.verify(authenticated_msg['payload'].encode('utf-8'),
                                                authenticated_msg['project_signature'])





class TestAdminSession(unittest.TestCase):
    def setUp(self):
        mock_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.id_key_bytes)
        self.credentials = keychain.Credentials('me', mock_keypair)
        self.custom_config = dict()
        global_config = self.custom_config['GLOBAL'] = dict()
        global_config['base_url'] = 'https://myservice'

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
        self.assertEqual(response, 'hello world')













