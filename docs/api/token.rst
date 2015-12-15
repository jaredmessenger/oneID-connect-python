Token
=====
.. module:: oneid.keychain

``Token`` is the combination of a private key and matching public key.
To sign a message you need the private key file (.pem). To verify
a message, the receiver needs the senders public key.

.. class:: Token(*args, **kwargs)

    Token objects sign messages using the supplied private key
    or verifies messages using the supplied public key.

    .. doctest::

        >>> from oneid.keychain import Token
        >>> device_identity_token = Token.from_secret_pem('/Users/me/.ssh/device_id.pem')
        >>> signature = device_identity_token.sign('hello world')
        >>> print(signature)

    .. py:classmethod:: from_secret_pem(path)

        Reads in the secret key (aka private key), must be kept a secret and stored
        in a secure location. Enables the sender's :class:`~oneid.keychain.Token`
        to digitally sign messages that the receiver can use verify the sender's identity.

        :param path: Absolute file path to the secret key pem file.
        :return: :class:`~oneid.keychain.Token` instance

    .. py:classmethod:: from_secret_der(der_key)

        Reads the secret der key (aka private key), must be kept a secret and stored
        in a secure location.

        :param der_key: DER formatted secret key.
        :return: :class:`~oneid.keychain.Token`

    .. py:classmethod:: from_public_key(public_key)

        Creates a :class:`~oneid.keychain.Token` instance from a public key.

        :param public_key: :class:`~base64` URL encoded public key.

        :return: An instance of :class:`~oneid.keychain.Token` that can verify messages
            signed by the matching private key.

    .. py:method:: sign(payload)

        Create a digital signature that the message receiver can use to verify
        the sender's identity.

        :type payload:
        :param payload: The message, str() format.
        :return: Base64 digital signature.

    .. py:method:: verify(payload, signature)

        Verify the sender's digital signature.

        :param payload: The message, str() format.
        :param signature: Base64 digital signature from the sender
        :raises cryptography.exceptions.InvalidSignature: This is raises if the digital
            signature does NOT match the message digest.





