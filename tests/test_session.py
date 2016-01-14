import json
import base64
import unittest

from oneid import session, service, utils, keychain


class TestSession(unittest.TestCase):
    key_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGS'\
                'M49AwEHBG0wawIBAQQgbKk/yDq5mmGkhs7b\nLNiCMv25GvwYZNtS5JYUh' \
                '4OLafKhRANCAAQ0B+TfNujp2TNlw+zufTwzZSv3yU9U\ncbl+Ip5kv8Snp' \
                'p8ksaAGI+DSL7KCih3DXWr9b3Mwjcx0Uxzyrh0Y40z4\n' \
                '-----END PRIVATE KEY-----'

    def setUp(self):
        mock_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.key_bytes)
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

    def test_session_config(self):
        sess = session.AdminSession(self.credentials,
                                    config=self.custom_config)
        self.assertIsInstance(sess.test_service, service.BaseService)
        self.assertEqual(sess.test_service.__class__.__name__, 'test_service')

    def test_session_missing_arg(self):
        sess = session.AdminSession(self.credentials,
                                    config=self.custom_config)
        self.assertRaises(TypeError, sess.test_service.test_method)

    def test_admin_prepare(self):
        nonce = utils.make_nonce()
        alg = {'typ': 'JWT', 'alg': 'ES256'}
        claims = {'jti': nonce, 'iss': 'unit tester'}

        alg_serialized = json.dumps(alg)
        claims_serialized = json.dumps(claims)

        alg_b64 = base64.b64encode(alg_serialized)
        claims_b64 = base64.b64encode(claims_serialized)

        valid_payload = '{alg_b64}.{claims_b64}'.format(alg_b64=alg_b64,
                                                        claims_b64=claims_b64)

        sess = session.AdminSession(self.credentials)
        jwt = sess.prepare_message(**claims)

        sess_alg, sess_claims = jwt.split('.')[:2]
        test_payload = '{alg_b64}.{claims_b64}'.format(alg_b64=sess_alg,
                                                       claims_b64=sess_claims)
        self.assertEqual(valid_payload, test_payload)

    def test_verify_jwt(self):
        valid_jwt = 'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiBudW' \
                    'xsLCAidGVzdF9jbGFpbSI6ICJ0ZXN0X3ZhbHVlIiwgImp0aSI6ICIwM' \
                    'DEyMDE2LTAxLTEzVDAyOjEzOjIxWlZkeG1JciJ9.WiJ_5yTc29VcWLe' \
                    'MiuLE5eP0QUJop_tJT-QBFA2-9rrqjSy7SZ7ADVDkqmd8ZwWvl7J_wf' \
                    'a3GLeNQNkxIJwhSw'

        service.verify_jwt(valid_jwt, self.credentials.keypair)









