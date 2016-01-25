import json
import copy

import unittest
import mock
import logging

logger = logging.getLogger(__name__)


class MockResponse:
    def __init__(self, response, status_code):
        self.content = copy.deepcopy(response)
        self.status_code = status_code

    def json(self):
        return json.loads(self.content)


def mock_request_success(url, data=None, auth=None):
    response = json.loads(data)
    response.update({
        "errorcode": 0,
    })
    return MockResponse(json.dumps(response), 200)


def mock_request_failure(url, data=None, auth=None):
    response = json.loads(data)
    response.update({
        "errorcode": -99,
    })
    return MockResponse(json.dumps(response), 200)


class TestAuth(unittest.TestCase):
    def setUp(self):
        from oneid.auth import OneIDAuthenticationService
        self.service = OneIDAuthenticationService('aaa', 'bbb', 'ccc')

    def test_set_credentials(self):
        new_api_id = '123'
        new_api_key = '456'
        self.service.set_credentials(new_api_id, new_api_key)

        self.assertEqual(self.service.api_id, new_api_id)
        self.assertEqual(self.service.api_key, new_api_key)

    def test_set_bad_credentials(self):
        new_api_id = False
        new_api_key = ''

        with self.assertRaises(ValueError):
            self.service.set_credentials(new_api_id, new_api_key)

    @mock.patch('requests.post', side_effect=mock_request_success)
    def test_authentication_success(self, mock_request):
        data = {
            "nonces": 1,
            "uid": 2,
            "attr_claim_tokens": 3,
        }
        result = self.service.validate(data)
        self.assertNotEqual(result, data)
        data.update({
            "errorcode": 0,
        })
        self.assertEqual(result, data)

    @mock.patch('requests.post', side_effect=mock_request_success)
    def test_authentication_success_minimal(self, mock_request):
        data = {
            "nonces": 1,
            "uid": 2,
        }
        result = self.service.validate(data)
        self.assertNotEqual(result, data)
        data.update({
            "errorcode": 0,
        })
        self.assertEqual(result, data)

    @mock.patch('requests.post', side_effect=mock_request_success)
    def test_authentication_success_json(self, mock_request):
        data = {
            "nonces": 1,
            "uid": 2,
            "attr_claim_tokens": 3,
        }
        result = self.service.validate(json.dumps(data))
        self.assertNotEqual(result, data)
        data.update({
            "errorcode": 0,
        })
        self.assertEqual(result, data)

    @mock.patch('requests.post', side_effect=mock_request_failure)
    def test_authentication_failure(self, mock_request):
        data = {
            "nonces": 1,
            "uid": 2,
            "attr_claim_tokens": 3,
        }
        result = self.service.validate(data)
        self.assertNotEqual(result, data)
        data.update({
            "errorcode": -99,
            "failed": "failed",
        })
        self.assertEqual(result, data)
