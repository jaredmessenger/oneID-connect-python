Sending and Verifying IoT Device Telemetry Data
===============================================

This is a more practical example than "hello world". We're going
to send a message that is digitally signed from the IoT device, over HTTP, and
read the message after verifying the IoT device signature on a server.

IoT Device
----------
First we need to create **TWO** secret key pem files on the IoT Device.
The first is used to authenticate the identity of the IoT device, the second
is use to authenticate the application currently running. These are secret keys
and are both used to sign messages.

.. danger::
    It's a **SECRET KEY** therefore it needs to be stored in a secure place.

Generating a new key is exactly the same as in the :ref:`hello-world` example.

.. code-block:: python

    from oneid import service

    # Save the secret key bytes to a secure file
    id_key_pem_path = '/home/me/id_secret_key.pem'
    service.create_secret_key(output=id_key_pem_path)

    app_key_pem_path = '/home/me/app_secret_key.pem'
    service.create_scret_key(output=app_key_pem_path)


Now that the IoT device its secret keys, the device can begin signing messages.

There are many different ways you can send a message and it's matching
signature to the server. For this example we're going to use `JWT`_
packaged as JSON since there are going to be two signatures instead of one.

.. code-block:: python

    from oneid.keychain import Keypair, Credentials
    from oneid.session import DeviceSession

    # Subclass DeviceSession and override send_message
    class MyIOTDeviceSession(DeviceSession):
        def send_message(self, *args, **kwargs):
            """
            Override send_message to implement our own.
            """
            http_body = self.prepare_message()
            self.make_http_request('POST',
                                   'localhost:8080/telemetry_data',
                                   body=http_body)

    # The message we want to send to the server
    message = "Hello World"

    # device_id is a UUID the server can use to lookup this device
    # randomly generated from uuid.uuid4()
    device_id = '4dddaf21-2dd8-4439-9378-a869a6798f92'

    # load the IoT Identity Keypair
    id_keypair = Keypair.load_secret_pem(id_key_pem_path)
    id_credentials = Credentials(device_id, id_keypair)

    # Load the Application Keypair
    app_keypair = Keypair.load_secret_pem(app_key_pem_path)
    app_credentials = Credentials(device_id, app_keypair)

    # Create a session and send the message.
    session = MyIOTDeviceSession(id_credentials,
                                 application_credentials=app_credentials)
    session.send_message(message=message, device_id=device_id)

The IoT device is now setup to send digitally signed messages. There is one final
step we need to do before we move onto the server implementation.
The IoT device needs to share it's public keys (public keys enable the server to verify the identity
of the IoT device that sent the message).

.. code-block:: python

    import base64

    print('ID PUBLIC VERIFIER:')
    print(base64.b64encode(id_keypair.public_key_der))
    print('APP PUBLIC VERIFIER:')
    print(base64.b64encode(app_keypair.public_key_der))



Server
------
Setting up a server from scratch is out of scope for this example. We're going to assume
that you have a basic Python web server `(Django is being used here)`_
that can receive an HTTP POST request.

.. rubric:: File - site_name/views.py

.. code-block:: python

    import json
    from django.http import HttpResponse, HttpResponseBadRequest

    from oneid.keychain import Keypair, Credentials
    from oneid.service import verify_jwt
    from oneid.session import ServerSession

    # device_lookup is the device_id and it's matching public key that was printed
    # to the console in the last step, Production setup should store this in a database.
    device_lookup = {'4dddaf21-2dd8-4439-9378-a869a6798f92':
                     'Bnz0tlass2x7LbZJuOTR04Od/MzbO9msHiSXSttLbJEDPC0PlRvso'
                     '+u9c6+6Mq7AaONnd/nt1I0bQg6WXO31pw=='}

    class MyServerSession(ServerSession):
        def verify_message(self, message):
            # deserialize the JSON message
            data = json.dumps(message)

            payload = data.get('payload')
            app_sig = data.get('app_signature')
            id_sig = data.get('id_signature')

            alg, claims = payload.split('.')

            # deserialize claims to get device id
            claims_data = base64.b64decode(claims)

            device_id = claims_data.get('device_id')

            # Even though we copy/pasted the key, we're
            # still going to use the device_id and device_lookup for the key.
            device_key = device_lookup.get(device_id)

            # verify application signature first
            device_app_verifier = Keypair.from_public_der(base64.b64decode(device_key))

            # To verify the signature, we need the payload
            # and the application signature
            device_app_verifier.verify(payload, app_sig)

            # to verify the identity, we'll use oneID
            # build a jwt to verify identity with oneID
            jwt = '{payload}.{signature}'.format(payload=payload,
                                                 signature=id_sig)

            self.authenticate.edge_device(identity=device_id, body=jwt)


    # Create a new Server Session
    session = MyServerSession()

    # DJANGO REQUEST:
    def telemetry_data(request):
        """
        Receive JWT messages from IoT Devices and verify the device's signature
        """
        if request.method != 'POST':
            return HttpResponseBadRequest('Error')

        try:
            # Will raise exception if any verification fails
            session.verify(request.body)
        except Exception:
            return HttpResponse(status=403)

        return HttpResponse('SUCCESS!')


.. _hello-world:
.. _JWT: https://tools.ietf.org/html/rfc7519
.. _(Django is being used here): https://www.djangoproject.com
