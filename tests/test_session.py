import json
import logging

import unittest
import mock
import sure  # noqa

from cryptography.exceptions import InvalidSignature

from oneid import session, service, keychain, exceptions

logger = logging.getLogger(__name__)


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
        elif http_method.lower() == 'get':
            return MockResponse('tested', 200)
        else:
            return MockResponse('Method Not Allowed', 405)

    elif url == 'https://myservice/unauthorized':
        return MockResponse('Forbidden', 403)

    else:
        logger.debug('url not found: %s', url)
        return MockResponse('Not Found', 404)


class TestSession(object):
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

    reset_key_A_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGC' \
                        'CqGSM49AwEHBG0wawIBAQQgoipfyjtZXMp5pV/V\naTMQQXg3BX78u' \
                        'MgM7ePLw7y740ShRANCAATcaPOHf92vDJqOxvny/4BqQhuThy3o\nb' \
                        'zqDKss/lRiEd3hRpEcnFkA1/5J7YD27d+Rwce8c3Mv5Fw+0EvTEfxv' \
                        'j\n-----END PRIVATE KEY-----\n'

    reset_key_B_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGC' \
                        'CqGSM49AwEHBG0wawIBAQQgGnaOW5frHzPyaxsq\noL5AylzMQR3n+' \
                        'noiYg6CuUUaNlWhRANCAATk2/T8BgFV9DkdvRZvquFzXII+zuKG\nQ' \
                        '9asmASeRMfM3/HNmMGil82P7PTCGsuumbWhX+Ty0G3eZNE0FbLAK3o' \
                        '+\n-----END PRIVATE KEY-----\n'

    reset_key_C_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGC' \
                        'CqGSM49AwEHBG0wawIBAQQgySmjxLPOGxKxSqaT\nGGcjTJqbYGgFs' \
                        'njBTsZ+p4GJ9bqhRANCAASk4ktRaOwSpyB6yQ4kCbhsV0KH9eZs\n+' \
                        's7j/IlzbF0J0uwWeVYZifZxMS4dde/mWBvapkTa+oTiSEQoAwuVe4t' \
                        '3\n-----END PRIVATE KEY-----\n'


class TestBaseSession(unittest.TestCase):
    def test_invalid_method(self):
        base = session.SessionBase()
        base.make_http_request.when.called_with('BOGUS', None).should.throw(TypeError)

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_authentication_error(self, mock_request):
        base = session.SessionBase()
        base.make_http_request.when.called_with(
            'GET', 'https://myservice/unauthorized'
        ).should.throw(exceptions.InvalidAuthentication)


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

        mock_resetA_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.reset_key_A_bytes
        )
        self.resetA_credentials = keychain.Credentials('resetA-id', mock_resetA_keypair)

        mock_resetB_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.reset_key_B_bytes
        )
        self.resetB_credentials = keychain.Credentials('resetB-id', mock_resetB_keypair)

        mock_resetC_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.reset_key_C_bytes
        )
        self.resetC_credentials = keychain.Credentials('resetC-id', mock_resetC_keypair)

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

    def test_verify_rekey_signatures(self):
        message = {'payload': 'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ'
                              'pc3MiOiAib25laWQiLCAianRpIjogIjAwMTIwMTYtMDE'
                              'tMjBUMDA6NDU6MzhabjlxSGN5In0=',
                   'oneid_signature': '299qez5eIY1C0qC7GAYDN87LKxkMlQX_r1ESL3'
                                      'eFIbWkoY_hvWOZKrBkynyzetCbWHTZyb1yHp9B'
                                      '_7gUPIwmBQ',
                   'rekey_signatures': ['X7z82ZQ0y1zC6w2x-vK4Aq1JwS4RwA3utwcb'
                                        '7vIktEVXbd1e_4QAkJc3g1f00KlajIbZnvDd'
                                        'r4lKsePIR6s-VA',
                                        'YpbbBekxE-TvNwDpDI9sgzXt_iPFP9YAvfPa'
                                        '-tf9v89ETQ-hDX0RnIZ-1Le4HfQXL-i4ij10'
                                        'Y6VrQoLzN_Vesg',
                                        'JAMqXv1QLWmMDPThcG-wXDml4K436gqzHYOQ'
                                        'TkFtb5s6hdX3SuqMgijcQjuzUW6VU8K_8VGpm'
                                        'C0yiDZKSPUXtQ',
                                        ]

                   }
        data = json.dumps(message)
        sess = session.DeviceSession(self.id_credentials,
                                     application_credentials=self.app_credentials,
                                     oneid_credentials=self.oneid_credentials,
                                     project_credentials=self.proj_credentials)

        sess.verify_message(data, rekey_credentials=[self.resetA_credentials,
                                                     self.resetB_credentials,
                                                     self.resetC_credentials])

    def test_invalid_rekey_signature(self):
        message = {'payload': 'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ'
                              'pc3MiOiAib25laWQiLCAianRpIjogIjAwMTIwMTYtMDE'
                              'tMjBUMDA6NDU6MzhabjlxSGN5In0=',
                   'oneid_signature': '299qez5eIY1C0qC7GAYDN87LKxkMlQX_r1ESL3'
                                      'eFIbWkoY_hvWOZKrBkynyzetCbWHTZyb1yHp9B'
                                      '_7gUPIwmBQ',
                   'rekey_signatures': ['JAMqXv1QLWmMDPThcG-wXDml4K436gqzHYOQ'
                                        'TkFtb5s6hdX3SuqMgijcQjuzUW6VU8K_8VGp'
                                        'mC0yiDZKSPUXtQ',
                                        'qj0IBKcJTiqBTxoP193wZ5hkwgaCDnLswSBB'
                                        'sYXwQ0iOISmofCeZBYA_ZEo-F2k5AbBrvGBu'
                                        'ErG4FhkeQELYZw',
                                        'YpbbBekxE-TvNwDpDI9sgzXt_iPFP9YAvfPa'
                                        '-tf9v89ETQ-hDX0RnIZ-1Le4HfQXL-i4ij10'
                                        'Y6VrQoLzN_Vesg',
                                        ]

                   }

        sess = session.DeviceSession(self.id_credentials,
                                     application_credentials=self.app_credentials,
                                     oneid_credentials=self.oneid_credentials,
                                     project_credentials=self.proj_credentials)

        self.assertRaises(InvalidSignature, sess.verify_message, json.dumps(message),
                          rekey_credentials=[self.resetA_credentials,
                                             self.resetB_credentials,
                                             self.resetC_credentials])

    def test_missing_rekey_signature(self):
        message = {'payload': 'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ'
                              'pc3MiOiAib25laWQiLCAianRpIjogIjAwMTIwMTYtMDE'
                              'tMjBUMDA6NDU6MzhabjlxSGN5In0=',
                   'oneid_signature': '299qez5eIY1C0qC7GAYDN87LKxkMlQX_r1ESL3'
                                      'eFIbWkoY_hvWOZKrBkynyzetCbWHTZyb1yHp9B'
                                      '_7gUPIwmBQ',
                   'rekey_signatures': ['X7z82ZQ0y1zC6w2x-vK4Aq1JwS4RwA3utwcb'
                                        '7vIktEVXbd1e_4QAkJc3g1f00KlajIbZnvDd'
                                        'r4lKsePIR6s-VA',
                                        'YpbbBekxE-TvNwDpDI9sgzXt_iPFP9YAvfPa'
                                        '-tf9v89ETQ-hDX0RnIZ-1Le4HfQXL-i4ij10'
                                        'Y6VrQoLzN_Vesg',
                                        'JAMqXv1QLWmMDPThcG-wXDml4K436gqzHYOQ',
                                        ]

                   }

        sess = session.DeviceSession(self.id_credentials,
                                     application_credentials=self.app_credentials,
                                     oneid_credentials=self.oneid_credentials,
                                     project_credentials=self.proj_credentials)

        self.assertRaises(InvalidSignature, sess.verify_message, json.dumps(message),
                          rekey_credentials=[self.resetA_credentials,
                                             self.resetB_credentials,
                                             self.resetC_credentials])

    def test_missing_rekey_credential(self):
        message = {'payload': 'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ'
                              'pc3MiOiAib25laWQiLCAianRpIjogIjAwMTIwMTYtMDE'
                              'tMjBUMDA6NDU6MzhabjlxSGN5In0=',
                   'oneid_signature': '299qez5eIY1C0qC7GAYDN87LKxkMlQX_r1ESL3'
                                      'eFIbWkoY_hvWOZKrBkynyzetCbWHTZyb1yHp9B'
                                      '_7gUPIwmBQ',
                   'rekey_signatures': ['X7z82ZQ0y1zC6w2x-vK4Aq1JwS4RwA3utwcb'
                                        '7vIktEVXbd1e_4QAkJc3g1f00KlajIbZnvDd'
                                        'r4lKsePIR6s-VA',
                                        'YpbbBekxE-TvNwDpDI9sgzXt_iPFP9YAvfPa'
                                        '-tf9v89ETQ-hDX0RnIZ-1Le4HfQXL-i4ij10'
                                        'Y6VrQoLzN_Vesg',
                                        'JAMqXv1QLWmMDPThcG-wXDml4K436gqzHYOQ'
                                        'TkFtb5s6hdX3SuqMgijcQjuzUW6VU8K_8VGpm'
                                        'C0yiDZKSPUXtQ',
                                        ]

                   }
        sess = session.DeviceSession(self.id_credentials,
                                     application_credentials=self.app_credentials,
                                     oneid_credentials=self.oneid_credentials,
                                     project_credentials=self.proj_credentials)

        self.assertRaises(InvalidSignature, sess.verify_message, json.dumps(message),
                          rekey_credentials=[self.resetA_credentials,
                                             self.resetB_credentials])


class TestServerSession(unittest.TestCase):
    def setUp(self):
        mock_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.id_key_bytes)
        self.server_credentials = keychain.Credentials('server', mock_keypair)

        mock_oneid_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.oneid_key_bytes)
        self.oneid_credentials = keychain.Credentials('oneID', mock_oneid_keypair)

        mock_project_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.proj_key_bytes
        )
        self.project_credentials = keychain.Credentials('proj', mock_project_keypair)
        mock_resetA_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.reset_key_A_bytes
        )
        self.resetA_credentials = keychain.Credentials('resetA-id', mock_resetA_keypair)

        mock_resetB_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.reset_key_B_bytes
        )
        self.resetB_credentials = keychain.Credentials('resetB-id', mock_resetB_keypair)

        mock_resetC_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.reset_key_C_bytes
        )
        self.resetC_credentials = keychain.Credentials('resetC-id', mock_resetC_keypair)

        self.oneid_response = 'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3Mi' \
                              'OiAib25lSUQiLCAianRpIjogIjAwMTIwMTYtMDEtMjBUMjE6N' \
                              'TE6MDZabDJ5dHlXIn0=.eEhASqRrKWPhzKVmSmeFZY5tGeTgo' \
                              'nZS45qwnz0_4VJb_qM_kNnQqLp96mPZLUtKHVIeJqA77SqlVx' \
                              'WsOB1J4g'

        self.fake_config = {
            'GLOBAL': {
                'base_url': 'https://myservice',
            },
            'test_service': {
                'test_method': {
                    'endpoint': '/my/endpoint',
                    'method': 'GET',
                    'arguments': {},
                },
            },
        }

    def test_init_from_config(self):
        sess = session.ServerSession(config={})
        sess.should_not.have.property('test_service')

        sess = session.ServerSession(
            identity_credentials=self.server_credentials,
            config=self.fake_config,
        )
        sess.should.have.property('test_service')

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_service_request(self, mock_request):
        sess = session.ServerSession(
            identity_credentials=self.server_credentials,
            config=self.fake_config,
        )
        sess.test_service.test_method().should.equal('tested')

    def test_prepare_message(self):
        sess = session.ServerSession(identity_credentials=self.server_credentials,
                                     oneid_credentials=self.oneid_credentials,
                                     project_credentials=self.project_credentials)

        authenticated_data = sess.prepare_message(oneid_response=self.oneid_response)

        authenticated_msg = json.loads(authenticated_data)

        self.assertIn('payload', authenticated_msg)
        self.assertIn('project_signature', authenticated_msg)
        self.assertIn('oneid_signature', authenticated_msg)

        self.project_credentials.keypair.verify(authenticated_msg['payload'],
                                                authenticated_msg['project_signature'])
        self.oneid_credentials.keypair.verify(authenticated_msg['payload'],
                                              authenticated_msg['oneid_signature'])

    def test_prepare_message_no_project(self):
        sess = session.ServerSession(identity_credentials=self.server_credentials,
                                     oneid_credentials=self.oneid_credentials)

        sess.prepare_message.when.called_with().should.throw(AttributeError)

    def test_reset_keys(self):
        sess = session.ServerSession(identity_credentials=self.server_credentials,
                                     oneid_credentials=self.oneid_credentials,
                                     project_credentials=self.project_credentials)

        authenticated_data = sess.prepare_message(
            oneid_response=self.oneid_response,
            rekey_credentials=[
                self.resetA_credentials,
                self.resetB_credentials,
                self.resetC_credentials,
            ]
        )
        msg = json.loads(authenticated_data)

        msg.should.have.key('payload')
        msg.should.have.key('oneid_signature')
        msg.should.have.key('reset_signatures').being.a(list)

        msg['reset_signatures'].should.have.length_of(3)

        payload = msg['payload']
        self.oneid_credentials.keypair.verify(payload, msg['oneid_signature']).should.be.true

        reset_sigs = msg['reset_signatures']

        self.resetA_credentials.keypair.verify(payload, reset_sigs[0]).should.be.true
        self.resetB_credentials.keypair.verify(payload, reset_sigs[1]).should.be.true
        self.resetC_credentials.keypair.verify(payload, reset_sigs[2]).should.be.true


class TestAdminSession(unittest.TestCase):
    def setUp(self):
        mock_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.id_key_bytes)
        self.credentials = keychain.Credentials('me', mock_keypair)
        mock_project_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.proj_key_bytes
        )
        self.project_credentials = keychain.Credentials('proj', mock_project_keypair)
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

    def test_admin_session_defaults(self):
        sess = session.AdminSession(self.credentials)
        sess.should.have.property('revoke').being.a(service.BaseService)
        sess.revoke.__class__.__name__.should.equal('revoke')

    def test_admin_session_config(self):
        sess = session.AdminSession(self.credentials,
                                    config=self.custom_config)
        self.assertIsInstance(sess.test_service, service.BaseService)
        self.assertEqual(sess.test_service.__class__.__name__, 'test_service')

    def test_project_credentials(self):
        sess = session.AdminSession(self.credentials)
        sess.project_credentials.should.be.none

        sess = session.AdminSession(self.credentials, project_credentials=self.project_credentials)
        sess.project_credentials.should.be(self.project_credentials)

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
