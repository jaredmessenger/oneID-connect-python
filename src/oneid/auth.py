from __future__ import unicode_literals

"""
Provides functionality to verify signatures from oneID users,
specifically as part of the Javascript API `signin()`_ callback.

.. _signin(): https://developer.oneid.com/docs/#/login/javascript-api/signin
"""
import copy
import json
import requests


class OneIDAuthenticationService:
    """
    Encapsulates a connection to the oneID servers

    :param api_id: Your OneID API ID credentials (from https://keychain.oneid.com/register)
    :param api_key: Your OneID API Key credentials (from https://keychain.oneid.com/register)
    :param server_flag: If you want to connect to a different API  should be (for example)
                        "-test" when using a non-production server
    """
    def __init__(self, api_id=None, api_key=None, server_flag=""):
        self.keychain_server = "https://keychain%s.oneid.com" % server_flag

        # Set the API credentials
        self.set_credentials(api_id, api_key)

    def _call_keychain(self, method, data={}):
        """
        Call the OneID Keychain Service. (i.e. to validate signatures)

        :param method: The OneID API call you wish to call
        :param data: Data for the OneID API CAll
        """
        url = "%s/%s" % (self.keychain_server, method)
        r = requests.post(url, json.dumps(data), auth=(self.api_id, self.api_key))
        return r.json()

    def set_credentials(self, api_id="", api_key=""):
        """
        Set the credentials used for access to the OneID Helper Service

        :param api_id: Your OneID API ID
        :param api_key: Your OneID API key
        """
        if not api_id or not api_key:
            raise ValueError('api_id and api_key are required')

        self.api_id = api_id
        self.api_key = api_key

    def validate(self, oneid_payload):
        """
        Validate the data received by a callback

        :param oneid_payload: The dictionary you want to validate,
            typically the payload from a OneID sign in call
        :return: if successful, `oneid_payload`, updated with the response from oneID.
            Otherwise, the error response from oneID.
        """
        if isinstance(oneid_payload, dict):
            oneid_payload = copy.deepcopy(oneid_payload)
        else:
            oneid_payload = json.loads(oneid_payload)

        data_to_validate = {
            "nonces": oneid_payload["nonces"],
            "uid": oneid_payload["uid"]
        }

        if "attr_claim_tokens" in oneid_payload:
            data_to_validate["attr_claim_tokens"] = oneid_payload["attr_claim_tokens"]

        keychain_response = self._call_keychain("validate", data_to_validate)

        if not self.success(keychain_response):
            keychain_response["failed"] = "failed"
            return keychain_response

        oneid_payload.update(keychain_response)

        return oneid_payload

    def success(self, oneid_response):
        """
        Check errorcode in a response

        :param oneid_response: A response from :py:meth:`validate()`
        :return: True if the response indicates success, False otherwise.
        """
        return oneid_response.get("errorcode", -1) == 0
