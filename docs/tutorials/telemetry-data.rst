Sending and Verifying IoT Device Telemetry Data
===============================================

This is a more practical example than "hello world". We're going
to send a message that is digitally signed from the IoT device, over HTTP, and
read the message after verifying the IoT device signature on a server.

IoT Device
----------
First we need to create a secret key pem file on the IoT Device.
This secret key is used to sign messages.
**IT'S A SECRET KEY THEREFORE MUST BE STORED IS IN A SECURE PLACE.**

Generating a new key is exactly the same as in the "hello world" example, but
this key needs to be stored securely on the IoT device.

.. code-block:: python

    from oneid import service

    # Save the secret key bytes to a secure file
    secret_key_pem_path = '/home/me/device_secret_key.pem'
    service.create_secret_key(output=secret_key_pem_path)



Now that the IoT device has a secret key, the device can begin signing messages.

There are many different ways you can send a message and it's matching
signature to the server. For this example we're going to use `JWT`_.
There are Python JWT libraries available, but for simplicity sake,
we're just going to quickly implement a single JWT message.

.. code-block:: python

    from oneid.keychain import Token
    from oneid.session import Session

    # The message we want to send to the server
    message = "Hello World"

    # device_id is a UUID the server can use to lookup this device
    # randomly generated from uuid.uuid4()
    device_id = '4dddaf21-2dd8-4439-9378-a869a6798f92'

    # load the device oneID Token
    device_token = Token()
    device_token.identity = device_id
    device_token.load_secret_pem(secret_key_pem_path)

    session = Session(device_token)
    jwt = session.build_jwt(message=message, device=device_id)

    print(jwt)

The IoT device is now setup to send digitally signed messages. There is one final
step we need to do before we move onto the server implementation.
The IoT device needs to share it's public key and ``device_id`` to the server.
This is required for the sever to verify messages it receives from the IoT device.

.. code-block:: python

    # We're just going to print so we can copy and paste
    print(device_id)

    print(base64.b64encode(device_token.public_key_der))

Server
------
Setting up a server from scratch is out of scope for this example. We're going to assume
that you have a basic Python web server `(Django is being used here)`_
that can receive an HTTP POST request.

.. rubric:: File - site_name/views.py

.. code-block:: python

    from django.http import HttpResponse, HttpResponseBadRequest

    from oneid.token import Token
    from oneid.service import verify_jwt

    # device_lookup is the device_name and it's matching public key that was printed
    # to the console in the last step, Production setup should store this in a database.
    device_lookup = {'4dddaf21-2dd8-4439-9378-a869a6798f92':
                     'Bnz0tlass2x7LbZJuOTR04Od/MzbO9msHiSXSttLbJEDPC0PlRvso'
                     '+u9c6+6Mq7AaONnd/nt1I0bQg6WXO31pw=='}

    def telemetry_data(request):
        """
        Receive JWT messages from IoT Devices and verify the device's signature
        """
        if request.method != 'POST':
            return HttpResponseBadRequest('Error')

        # Make sure the body is a valid JWT
        claims = verify_jwt(request.body)

        # given the device_id, lookup it's matching public key
        device_id = claims.get('device')
        device_public_key = device_lookup.get(device_name)

        # Load the public key into oneID Token
        device_token = Token.from_public_der(device_public_key)

        # now verify that the body was sent from the device
        verify_jwt(request.body, device_token)

        # The message and sender have been verified!
        print(claims.get('message'))
        return HttpResponse('SUCCESS!')




.. _JWT: https://tools.ietf.org/html/rfc7519
.. _(Django is being used here): https://www.djangoproject.com
