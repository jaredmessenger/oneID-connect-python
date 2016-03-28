# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import os
import tempfile
import uuid
import base64
import logging

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

import unittest
import sure  # noqa

from oneid import keychain, utils

logger = logging.getLogger(__name__)


class TestCredentials(unittest.TestCase):
    def setUp(self):
        self.uuid = uuid.uuid4()
        self.keypair = keychain.Keypair()

    def test_basic_object(self):
        creds = keychain.Credentials(self.uuid, self.keypair)
        creds.id.should.equal(self.uuid)
        creds.keypair.should.equal(self.keypair)

    def test_invalid_keypair(self):
        keychain.Credentials.when.called_with(self.uuid, None).should.throw(ValueError)


class TestProjectCredentials(TestCredentials):
    def setUp(self):
        super(TestProjectCredentials, self).setUp()
        self.encryption_key = os.urandom(32)
        self.data = 'super 🔥 data'
        self.project_credentials = keychain.ProjectCredentials(
            self.uuid,
            self.keypair,
            self.encryption_key
        )

    def test_encrypt(self):
        enc = self.project_credentials.encrypt(self.data)
        enc.should.have.key('cipher').with_value.equal('aes')
        enc.should.have.key('mode').with_value.equal('gcm')
        enc.should.have.key('ts').with_value.equal(128)

        cleartext = utils.to_string(self.project_credentials.decrypt(enc['ct'], enc['iv']))
        cleartext.should.equal(self.data)

    def test_encrypt_bytes(self):
        data = ['string', b'bytes']

        for text in data:
            logger.debug('enc/dec %s', text)
            enc = self.project_credentials.encrypt(text)
            cleartext = utils.to_string(self.project_credentials.decrypt(enc['ct'], enc['iv']))
            cleartext.should.equal(utils.to_string(text))

    def test_decrypt_dict(self):
        enc = self.project_credentials.encrypt(self.data)

        cleartext = utils.to_string(self.project_credentials.decrypt(enc))
        cleartext.should.equal(self.data)

    def test_decrypt_dict_invalid(self):
        self.project_credentials.decrypt.when.called_with({}).should.throw(ValueError)
        self.project_credentials.decrypt.when.called_with({
            'cipher': 'BES', 'mode': 'gcm', 'ts': 128, 'iv': 'aa', 'ct': 'aa',
        }).should.throw(ValueError)
        self.project_credentials.decrypt.when.called_with({
            'cipher': 'aes', 'mode': 'HCM', 'ts': 128, 'iv': 'aa', 'ct': 'aa',
        }).should.throw(ValueError)
        self.project_credentials.decrypt.when.called_with({
            'cipher': 'aes', 'mode': 'gcm', 'ts': 129, 'iv': 'aa', 'ct': 'aa',
        }).should.throw(ValueError)

    def test_decrypt_no_iv(self):
        self.project_credentials.decrypt.when.called_with('aa').should.throw(ValueError)
        self.project_credentials.decrypt.when.called_with('aa', None).should.throw(ValueError)


class TestKeypair(unittest.TestCase):
    BASE_PATH = os.path.dirname(__file__)
    x509_PATH = os.path.join(BASE_PATH, 'x509')

    def test_load_pem_path(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        keychain.Keypair.from_secret_pem(path=pem_path).should.be.a(keychain.Keypair)

    def test_load_pem_path_pkcs8(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_pkcs8_private_key.pem')
        keychain.Keypair.from_secret_pem(path=pem_path).should.be.a(keychain.Keypair)

    def test_load_pem_path_missing(self):
        pem_path = None
        with tempfile.NamedTemporaryFile(suffix='.pem') as tf:
            pem_path = tf.name
        keychain.Keypair.from_secret_pem(path=pem_path).should.be.none

    def test_load_pem_bytes(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        with open(pem_path, 'rb') as f:
            pem_data = f.read()
            keychain.Keypair.from_secret_pem(key_bytes=pem_data).should.be.a(keychain.Keypair)

    def test_load_pem_bytes_pkcs8(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_pkcs8_private_key.pem')
        with open(pem_path, 'rb') as f:
            pem_data = f.read()
            keychain.Keypair.from_secret_pem(key_bytes=pem_data).should.be.a(keychain.Keypair)

    def test_load_pem_public_path(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_public_key.pem')
        keychain.Keypair.from_public_pem(path=pem_path).should.be.a(keychain.Keypair)

    def test_load_public_pem_bytes(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_public_key.pem')
        with open(pem_path, 'rb') as f:
            pem_data = f.read()
            keychain.Keypair.from_public_pem(key_bytes=pem_data).should.be.a(keychain.Keypair)

    def test_load_public_pem_path_missing(self):
        pem_path = None
        with tempfile.NamedTemporaryFile(suffix='.pem') as tf:
            pem_path = tf.name
        keychain.Keypair.from_public_pem(path=pem_path).should.be.none

    def test_load_der_bytes(self):
        der_path = os.path.join(self.x509_PATH, 'ec_sha256.der')
        with open(der_path, 'rb') as f:
            der_data = f.read()
            keychain.Keypair.from_secret_der(der_data).should.be.a(keychain.Keypair)

    def test_export_pem(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        with open(pem_path, 'rb') as f:
            pem_bytes = f.read()
            token = keychain.Keypair.from_secret_pem(key_bytes=pem_bytes)
            token.secret_as_pem.should.equal(pem_bytes)

    def test_export_der(self):
        der_path = os.path.join(self.x509_PATH, 'ec_sha256.der')
        with open(der_path, 'rb') as f:
            der_bytes = f.read()
            token = keychain.Keypair.from_secret_der(der_bytes)
            token.secret_as_der.should.equal(der_bytes)

    def test_sign_verify(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        with open(pem_path, 'rb') as f:
            pem_bytes = f.read()
            token = keychain.Keypair.from_secret_pem(key_bytes=pem_bytes)

            signature = token.sign(b'MESSAGE')
            token.verify(b'MESSAGE', signature).should.be.true

    def test_public_key(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_public_key.pem')
        pubkeypair = keychain.Keypair.from_public_pem(path=pem_path)
        pubkeypair.public_key.should.be.an(EllipticCurvePublicKey)

        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        seckeypair = keychain.Keypair.from_secret_pem(path=pem_path)
        seckeypair.public_key.should.be.an(EllipticCurvePublicKey)

        # for branch coverage
        nullkeypair = keychain.Keypair()
        nullkeypair.public_key.should.be.none

    def test_public_key_der(self):
        der = base64.b64decode(
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJLzzbuz2tRnLFlOL+6bTX6giVavA'
            'sc6NDFFT0IMCd2ibTTNUDDkFGsgq0cH5JYPg/6xUlMBFKrWYe3yQ4has9w=='
        )
        keypair = keychain.Keypair.from_public_der(der)
        keypair.public_key_der.should.equal(der)

    def test_public_key_pem(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_public_key.pem')
        with open(pem_path, 'rb') as f:
            pem = f.read()
            keypair = keychain.Keypair.from_public_pem(pem)
            keypair.public_key_pem.should.equal(pem)
