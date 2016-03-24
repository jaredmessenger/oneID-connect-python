# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import tempfile
import logging

import unittest
import mock
import sure  # noqa

from oneid import service, session, keychain, utils

from .test_session import TestSession, mock_request  # TODO: this is starting to look like a fixture

logger = logging.getLogger(__name__)


class TestServiceCreator(unittest.TestCase):
    def setUp(self):
        mock_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.id_key_bytes)
        self.credentials = keychain.Credentials('me', mock_keypair)
        self.model = {
            'test_method': {
                'endpoint': 'https://myservice/my/endpoint',
                'method': 'GET',
                'arguments': {
                    'in_jwt': {
                        'location': 'jwt',
                        'required': True,
                    },
                    'in_url': {
                        'location': 'url',
                        'required': True,
                    },
                    'optional': {
                        'location': 'jwt',
                        'required': False,
                    },
                },
            }
        }
        self.session = session.ServerSession(self.credentials)
        self.service_creator = service.ServiceCreator()
        self.service = self.service_creator.create_service_class('svc', self.model, self.session)

    def test_created_service_class(self):
        self.service.__class__.__name__.should.equal('svc')
        self.service.should.have.property('test_method')

    def test_service_class_with_project_creds(self):
        mock_proj_keypair = keychain.Keypair.from_secret_pem(key_bytes=TestSession.proj_key_bytes)
        proj_credentials = keychain.Credentials('proj-id', mock_proj_keypair)
        sess = session.ServerSession(self.credentials, project_credentials=proj_credentials)
        svc = self.service_creator.create_service_class('svc', self.model, sess)
        svc.__class__.__name__.should.equal('svc')
        svc.should.have.property('test_method')

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_call_created_method(self, mock_request):
        self.service.test_method(in_jwt='a', in_url='b', optional=None).should.equal('tested')

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_call_created_method_missing_args(self, mock_request):
        self.service.test_method.when.called_with().should.throw(TypeError)

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_call_created_method_with_body(self, mock_request):
        self.service.test_method(body='hello').should.equal('tested')


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


class TestCreateSecretKey(unittest.TestCase):
    def test_basic_call(self):
        kp = service.create_secret_key()
        self.assertIsInstance(kp, keychain.Keypair)

    def test_save_to_file(self):
        fp = tempfile.NamedTemporaryFile()
        filename = fp.name
        fp.close()

        kp = service.create_secret_key(output=filename)

        with open(filename, 'rb') as f:
            key_data = f.read()
            key_data.should.equal(kp.secret_as_pem)


class TestEncryptDecryptAttributes(unittest.TestCase):
    def setUp(self):
        self.key = service.create_aes_key()
        self.data = 'hoôray!🎉'

    def test_encrypt(self):
        enc = service.encrypt_attr_value(self.data, self.key)
        enc.should.have.key('cipher').with_value.equal('aes')
        enc.should.have.key('mode').with_value.equal('gcm')
        enc.should.have.key('ts').with_value.equal(128)

    def test_decrypt(self):
        enc = service.encrypt_attr_value(self.data, self.key)
        utils.to_string(service.decrypt_attr_value(enc, self.key)).should.equal(self.data)

    def test_decrypt_bytes(self):
        data = utils.to_bytes(self.data)
        enc = service.encrypt_attr_value(data, self.key)
        service.decrypt_attr_value(enc, self.key).should.equal(data)

    def test_decrypt_wrong_type(self):
        service.decrypt_attr_value.when.called_with(None, self.key).should.throw(ValueError)
        service.decrypt_attr_value.when.called_with('foo', self.key).should.throw(ValueError)
        service.decrypt_attr_value.when.called_with(b'foo', self.key).should.throw(ValueError)
        service.decrypt_attr_value.when.called_with(['foo'], self.key).should.throw(ValueError)

    def test_decrypt_incorrect_params(self):
        enc = {
            'cipher': 'hope',
            'mode': 'niave',
        }
        service.decrypt_attr_value.when.called_with(enc, self.key).should.throw(ValueError)
