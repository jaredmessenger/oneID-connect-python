# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import time
import base64
import json
import logging

from unittest import TestCase
import sure  # noqa

# from nose.tools import nottest

from oneid import service, keychain, utils

logger = logging.getLogger(__name__)

MSGS = [
    'hello there',
    'héllo!',
    '😬',
    '😬' * 2**20,  # 1M
]


class TestJWT(TestCase):
    def setUp(self):
        self.keypair = service.create_secret_key()

    def tearDown(self):
        pass

    def _create_and_verify_good_jwt(self, claims, keypair=None):
        keypair = keypair or self.keypair
        jwt = service.make_jwt(claims, keypair)
        service.verify_jwt(jwt, keypair).should.equal(claims)
        service.verify_jwt(jwt).should.equal(claims)

    def test_jwt_sunny_day(self):
        for msg in MSGS:
            logger.debug('testing jwt for "%s"', msg[:1000])
            self._create_and_verify_good_jwt({'message': msg})

    # def test_null_message(self):
    #     self._create_and_verify_good_jwt(None)
    #
    def test_sample_sjcl_token_one(self):
        sec_der = (
            'MHcCAQEEILVcaIaPYITt3Hxh6ocwALM1HSDwh0ZuxZSocIWMKCbVoAoGCCqGSM49'
            'AwEHoUQDQgAEoj9k67GCZ0J4giV6FzT1diXBNtAqUB/+CIrEkmSNDB4XU9hLfYPC'
            'COEaGaC+WoOShLcM2BRJ6DLodM9zqhYFrQ=='
        )
        pub_der = (
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoj9k67GCZ0J4giV6FzT1diXBNtAq'
            'UB/+CIrEkmSNDB4XU9hLfYPCCOEaGaC+WoOShLcM2BRJ6DLodM9zqhYFrQ=='
        )
        token = (
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.'
            'eyJpc3MiOiJvbmVJRCJ9.'
            '18Uo2vYWGizuUlAjqPHbsAPwDiabQ-nD89JP0rdBL0pTo7kMacPZlcA2YIuSDWHx2tqrRXwY49EqqW6Pz6LaTw'
        )
        pri = keychain.Keypair.from_secret_der(base64.b64decode(sec_der))
        service.verify_jwt(token, pri).should.be.true

        pub = keychain.Keypair.from_public_der(base64.b64decode(pub_der))
        service.verify_jwt(token, pub).should.be.true

    def test_sample_sjcl_token_two(self):
        sec_der = (
            'MHcCAQEEIA7WRfmTNEW2rMcRCbDuGZcJiRvEq/UBA/13vk0FYAP+oAoGCCqGSM49'
            'AwEHoUQDQgAEs3IdFC73cm7J9gMMt4l3h0VTVzM4goEZiTSp+fukB/l0W4m97qd8'
            'MSEXHak/D7/cOJYEVAWijVuYRVz0Ke9lkg=='
        )
        pub_der = (
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs3IdFC73cm7J9gMMt4l3h0VTVzM4'
            'goEZiTSp+fukB/l0W4m97qd8MSEXHak/D7/cOJYEVAWijVuYRVz0Ke9lkg=='
        )
        token = (
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.'
            'eyJpc3MiOiJvbmVJRCJ9.'
            'gkIx8hdH1gHuLl1GIOARztb2ljSPcfaNlMFgkn5m6Sqb-bmGbFzMu-b94WFBUbZrv3_X8LMCejnwbt_832vvkA'
        )

        pri = keychain.Keypair.from_secret_der(base64.b64decode(sec_der))
        service.verify_jwt(token, pri).should.be.true

        pub = keychain.Keypair.from_public_der(base64.b64decode(pub_der))
        service.verify_jwt(token, pub).should.be.true

    def test_empty_message(self):
        self._create_and_verify_good_jwt({'1': 1})
        self._create_and_verify_good_jwt({})

    def test_jwt_already_json_messages(self):
        service.verify_jwt(
            service.make_jwt('{"iss": "oneID", "message": "hello"}', self.keypair),
            self.keypair
        ).should.be.true
        service.verify_jwt(
            service.make_jwt(b'{"iss": "oneID", "message": "hello"}', self.keypair),
            self.keypair
        ).should.be.true

    def test_jwt_wrong_type(self):
        service.make_jwt.when.called_with(123, self.keypair).should.throw(Exception)
        service.make_jwt.when.called_with(123.456, self.keypair).should.throw(Exception)
        service.make_jwt.when.called_with(['a', 'b'], self.keypair).should.throw(Exception)
        service.make_jwt.when.called_with(lambda a: a, self.keypair).should.throw(Exception)

    def test_verify_jwt_string_or_bytes(self):
        jwt1 = service.make_jwt('{"iss": "oneID", "message": "hello"}', self.keypair)
        if isinstance(jwt1, bytes):
            jwt2 = jwt1.decode('utf-8')
        else:
            jwt2 = jwt1.encode('utf-8')
        service.verify_jwt(jwt1, self.keypair).should.be.true
        service.verify_jwt(jwt2, self.keypair).should.be.true

    def test_jwt_wrong_key(self):
        new_keypair = service.create_secret_key()
        msg = 'bad jwt here❌'

        service.verify_jwt(
            service.make_jwt(
                {'badmsg': msg},
                self.keypair
            ),
            new_keypair
        ).should.be.false
        service.verify_jwt(
            service.make_jwt(
                {'badmsg': msg},
                new_keypair
            ),
            self.keypair
        ).should.be.false

    def test_jwt_bad_header_wrong_value(self):
        jwt = service.make_jwt({'message': 'hi'}, self.keypair)
        header = json.dumps({
            'typ': 'JWT',
            'alg': 'NONE',
        })
        bad_jwt = '.'.join([utils.base64url_encode(header).decode('utf-8')] + jwt.split('.')[1:])
        service.verify_jwt(bad_jwt, self.keypair).should.be.false

    def test_jwt_bad_header_extra_keys(self):
        jwt = service.make_jwt({'message': 'hi'}, self.keypair)
        header = json.dumps({
            'typ': 'JWT',
            'alg': 'ES256',
            'bogosity': True,
        })
        bad_jwt = '.'.join([utils.base64url_encode(header).decode('utf-8')] + jwt.split('.')[1:])
        service.verify_jwt(bad_jwt, self.keypair).should.be.false

    def test_jwt_bad_header_not_json(self):
        jwt = service.make_jwt({'message': 'hi'}, self.keypair)
        bad_jwt = '.'.join(
            [utils.base64url_encode('woo-hoo! we just do what we want!!').decode('utf-8')] +
            jwt.split('.')[1:]
        )
        service.verify_jwt(bad_jwt, self.keypair).should.be.false

    def test_jwt_malformed_header(self):
        jwt = service.make_jwt({'message': 'hi'}, self.keypair)
        good_header = json.dumps(service.REQUIRED_JWT_HEADER_ELEMENTS)
        header = utils.base64url_encode(good_header).decode('utf-8')[:-4]
        bad_jwt = '.'.join([header] + jwt.split('.')[:2])
        service.verify_jwt(bad_jwt, self.keypair).should.be.false

    def test_injected_issuer_claim(self):
        with_iss = {
            'iss': 'not-oneid'
        }
        self._create_and_verify_good_jwt(with_iss)
        with_iss['iss'] = 'oneID'
        self._create_and_verify_good_jwt(with_iss)

    def test_jwt_invalid_base64(self):
        jwt = service.make_jwt({'message': 'hi'}, self.keypair)
        header = 'a'
        bad_jwt = '.'.join([header] + jwt.split('.')[:2])
        service.verify_jwt(bad_jwt, self.keypair).should.be.false

    def test_jwt_malformed_payload(self):
        jwt = service.make_jwt({'message': 'hi'}, self.keypair)
        header, payload, signature = jwt.split('.')
        payload = payload[:-8]
        bad_jwt = '.'.join([header, payload, signature])
        service.verify_jwt(bad_jwt, self.keypair).should.be.false

    def test_jwt_missing_signature(self):
        jwt = service.make_jwt({'message': 'hi'}, self.keypair)
        bad_jwt = '.'.join(jwt.split('.')[:2])
        service.verify_jwt(bad_jwt, self.keypair).should.be.false

    def test_not_quite_expired_then_expired(self):
        now = int(time.time())
        logger.debug('now=%s', now)
        jwt = service.make_jwt({'message': 'hi', 'exp': (now + 3)}, self.keypair)
        service.verify_jwt(jwt, self.keypair).should.be.true

        time.sleep(6)
        service.verify_jwt(jwt, self.keypair).should.be.false

    def test_expired(self):
        now = int(time.time())
        logger.debug('now=%s', now)
        jwt = service.make_jwt({'message': 'hi', 'exp': (now - 1)}, self.keypair)
        service.verify_jwt(jwt, self.keypair).should.be.false

    def test_use_before_in_future(self):
        now = int(time.time())
        logger.debug('now=%s', now)
        jwt = service.make_jwt({'message': 'hi', 'nbf': (now + (3*60))}, self.keypair)
        service.verify_jwt(jwt, self.keypair).should.be.false

    def test_valid_nonce(self):
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()) + '123456'
        logger.debug('nonce=%s', nonce)
        jwt = service.make_jwt({'message': 'hi', 'jti': nonce}, self.keypair)
        service.verify_jwt(jwt, self.keypair).should.be.true
        # service.verify_jwt(jwt, self.keypair).should.be.false  # TODO

    def test_invalid_nonce(self):
        nonce = '002' + time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()) + '123456'
        logger.debug('nonce=%s', nonce)
        jwt = service.make_jwt({'message': 'hi', 'jti': nonce}, self.keypair)
        service.verify_jwt(jwt, self.keypair).should.be.false

    def test_expired_nonce(self):
        now = int(time.time())
        then = now-(1*24*60*60)
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(then)) + '123456'
        logger.debug('nonce=%s', nonce)
        jwt = service.make_jwt({'message': 'hi', 'jti': nonce}, self.keypair)
        service.verify_jwt(jwt, self.keypair).should.be.false


class TestKnownJWTokens(TestCase):
    def setUp(self):
        self.keypair = keychain.Keypair.from_secret_der(base64.b64decode(
            'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOiXcCrreAqzw3xOT'
            'L44O8DFyDfBAPQgZ0AmPGZfWmMShRANCAARD66FPRWFIFrNcn+DjLTSb8lP3pha3'
            'joBvC7Cf4JR/LP7lECAc0mNfokw84+pLurAkP2rG1Y63n9KPwntflfRD='
        ))

    def tearDown(self):
        pass

    def test_previously_generated_good_vectors(self):
        # msg = '{"claim": '
        #       '"this is a decently long test string with some înterésting characters!😀"'
        #       ', "iss": "oneID"}'
        good_tokens = [
            'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJFUzI1NiJ9.'
            'eyJjbGFpbSI6ICJ0aGlzIGlzIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3'
            'aXRoIHNvbWUgw65udGVyw6lzdGluZyBjaGFyYWN0ZXJzIfCfmIAiLCAiaXNzIjog'
            'Im9uZUlEIn0.'
            'Y5_T3I4fKvDaV7C9iRO4CAE7ZyVDZSJaKb1lE8oefsHc9_7BdNzz9qcfS8DFutNG'
            'XPHp073AdkirIHiDKNSmmA',
            'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJFUzI1NiJ9.'
            'eyJjbGFpbSI6ICJ0aGlzIGlzIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3'
            'aXRoIHNvbWUgw65udGVyw6lzdGluZyBjaGFyYWN0ZXJzIfCfmIAiLCAiaXNzIjog'
            'Im9uZUlEIn0.'
            'qgD5uRmnhAyymQ1APU8Zy0WBycw2FNleym6AB31GfELgpkPaeZJqckOKeNT5c6yT'
            'h99wJHi0PjXtblD6ddlWzA',
            'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJFUzI1NiJ9.'
            'eyJjbGFpbSI6ICJ0aGlzIGlzIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3'
            'aXRoIHNvbWUgw65udGVyw6lzdGluZyBjaGFyYWN0ZXJzIfCfmIAiLCAiaXNzIjog'
            'Im9uZUlEIn0.'
            'Yaj0JiCMBAQslap3WiBTSnNAZUEQZ5rACI_oHbP5gKCXGo_bUVoSvGygUMVmDipn'
            'mxZmqQpVYEXNqTCKVVKLRQ',

            'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.'
            'eyJjbGFpbSI6ICJ0aGlzIGlzIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3'
            'aXRoIHNvbWUgXHUwMGVlbnRlclx1MDBlOXN0aW5nIGNoYXJhY3RlcnMhXHVkODNk'
            'XHVkZTAwIiwg'
            'ImlzcyI6ICJvbmVJRCJ9.eX1ob01UqDOoFY0IVKHw7ycl7jVjYb7UWhWTZZD1MaK'
            'GSmQ9XuNgica4USLbQlVLt5_n1ihar2lAedpgw5QGgg',
            'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.'
            'eyJjbGFpbSI6ICJ0aGlzIGlzIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3'
            'aXRoIHNvbWUgXHUwMGVlbnRlclx1MDBlOXN0aW5nIGNoYXJhY3RlcnMhXHVkODNk'
            'XHVkZTAwIiwg'
            'ImlzcyI6ICJvbmVJRCJ9.d79RLEQ00KDsZ81bZ9lN-SMTKTXEwJDaIjEkkfa1Iho'
            'zWKcf6vHwA0iqZxjYF6WD-8oErFlEpnTSw4pIG-b1Yw',
            'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.'
            'eyJjbGFpbSI6ICJ0aGlzIGlzIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3'
            'aXRoIHNvbWUgXHUwMGVlbnRlclx1MDBlOXN0aW5nIGNoYXJhY3RlcnMhXHVkODNk'
            'XHVkZTAwIiwg'
            'ImlzcyI6ICJvbmVJRCJ9.P2GvYyl34tQb47HC7qIJZ8yEh4T8tzzCgjLjgzJMFSm'
            '3BwK-svxjm3O09RWB_6dPAGYrN2RKYVwdFdQqpWtKeA',

            'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.'
            'eyJpc3MiOiAib25lSUQiLCAiY2xhaW0iOiAidGhpcyBpcyBhIGRlY2VudGx5IGxv'
            'bmcgdGVzdCBzdHJpbmcgd2l0aCBzb21lIFx1MDBlZW50ZXJcdTAwZTlzdGluZyBj'
            'aGFyYWN0ZXJz'
            'ITpncmlubmluZzoifQ.kSlrw28fvkDYE0BASk-qqdiBYJLzFdkkZLIvbRoEUNr0o'
            'y3C0ZmKy1Lx8zkGMdS2HQCZ49y_7W03Merch45s-g',
        ]

        for token in good_tokens:
            service.verify_jwt(token, self.keypair).should.be.true

    def test_previously_generated_bad_vectors(self):
        bad_tokens = [
            # different private key
            'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJjbGFpbSI6ICJ0aGlzIGl'
            'zIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3aXRoIHNvbWUgw65udGVyw6l'
            'zdGluZyBjaGFyYWN0ZXJzIfCfmIAiLCAiaXNzIjogIm9uZUlEIn0.MEYCIQCcozU'
            '44vPzvyiBwyb0sM0N_fJ5bDnmub0tbFNSs-xtBAIhAK37PVBOkcckGg1fodFHnI7'
            'kpohaDSFNlhmZUWvXJmIg',
            # TODO: invalid headers (missing required, extra keys, different values)
            # TODO: bad signatures
        ]

        for token in bad_tokens:
            service.verify_jwt(token, self.keypair).should.be.false
