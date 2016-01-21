Sending Two-Factor Authenticated Firmware update to IoT Device
==============================================================
Sending a firmware update to all of your devices should always be secure.
The last thing you want is a malicious update sent to your entire fleet of devices.

For this example, we're going to use oneID's two-factor authentication service.
oneID's two-factor authentication service enables you to manage all your servers
and IoT devices. If a server or IoT device has been compromised or taken out of
commission, you can easily revoke it's signing permissions.

Before we begin, you will need to ``oneID-cli`` and a `oneID developer account`_.

.. code-block:: console

   $ pip install oneid-cli



Intro to oneID's Two-Factor Authentication
------------------------------------------
Two-factor means that there will be two signatures for each message.
**BOTH** signatures must be verified before reading the message.
Since there are two signatures that need to be verified on the IoT device,
the IoT device will need to store two tokens that will be used for message verification.
oneID will provide you with both of these tokens for the IoT device.

Steps:
~~~~~~
#. Server prepares a message for the IoT device and signs it.
#. Server makes a two-factor authentication request to oneID with the prepared message.
#. oneID verifies the server's identity and responds with oneID's signature of the message
#. Server then re-signs the message with the shared project key.
#. Server sends the message with the two signatures to the IoT device.
#. IoT device verifies **BOTH** signatures.



Setup
-----
First we need to configure your terminal.

.. code-block:: console

   oneid-cli configure

This will prompt you for your ``ACCESS_KEY``, ``ACCESS_SECRET``, and ``ONEID_KEY``.
You can find all these in your `oneID developer console`_


Creating a Project
~~~~~~~~~~~~~~~~~~
All users, servers and edge devices need to be associated with a project.
Let's create a new project.

.. code-block:: console

   $ oneid-cli create-project --name "my epic project"

You will be given two keys. The first is your project **SECRET** key.
The second is a oneID verification public key.

.. danger::
  SAVE THE PROJECT SECRET KEY IN A SAFE PLACE.
  If you lose this key, you will lose your ability to send authenticated messages
  to your devices.

The oneID verification public key will be given to all your edge devices and used
to verify messages sent from a server.


Server
~~~~~~
The firmware update message we will send to the IoT devices will be very simple.
The message will be a url to the CDN where the firmware update is hosted
and a checksum the IoT device will use to verify the download.

Before we can sign any messages, we need to give the server an identity
oneID can verify.

.. code-block:: console

   $ oneid-cli provision --name "IoT server" --type server

This will generate a new **SECRET** ``.pem`` file.

.. danger::

   PLEASE STORE SECRET FILES IN A SAFE PLACE. Never post them in a public forum
   or give them to anyone.

If you created the server secret key on your personal computer, we need to copy it over to the
server along with the project key that was generated when you first created the project.

.. code-block:: console

    $ scp /Users/me/secret/server_secret.pem ubuntu@10.1.2.3:/home/www/server_secret.pem
    $ scp /Users/me/secret/project_secret.pem ubuntu@10.1.2.3:/home/www/project_secret.pem
    $ scp /Users/me/secret/oneid_public.pem ubuntu@10.1.2.3:/home/www/oneid_public.pem

In python, we're just going to hardcode the path to these keys for quick access.

.. code-block:: python

    from oneid.keychain import Keypair, Credentials
    from oneid.session import ServerSession

    # Secret keys we downloaded from oneID Developer Portal
    server_secret_key_path = '/home/www/server_key.pem'
    project_secret_key_path = '/home/www/project_key.pem'

    # Unique Server ID,
    # we generated ours from uuid.uuid4()
    SERVER_ID = 'c75a1dfe-b468-4820-9114-2c94c7e092dc'

    # Unique Project ID provided by oneID
    PROJECT_ID = 'd47fedd0-729f-4941-b4bd-2ec4fe0f9ca9'

    server_key = Keypair.from_secret_pem(path=server_secret_key_path)
    server_credentials = Credentials(SERVER_ID, server_key)

    project_key = Keypair.from_secret_pem(path=project_secret_key_path)
    project_credentials = Credentials(PROJECT_ID, project_key)

    session = ServerSession(identity_credentials=server_credentials,
                            project_credentials=project_credentials)

    # Request authentication from oneID
    auth_response = session.authenticate.server(message='http://mycompany.com/firmwareupdate')

    # Use oneID's authentication response to make the authenticated message
    authenticated_msg = session.prepare_message(oneid_response=auth_response)

The final step is to send the two-factor ``authenticated_msg``
to the IoT device. You can use any network protocol you want,
or a messaging protocol such as MQTT, RabbitMQ, Redis etc.


IoT Device
~~~~~~~~~~
Just like we did with the server we need to start with provisioning our IoT device.

.. code-block:: console

    $ oneid-cli provision --name "my edge device" --type device


Now we need to copy over the oneID verifier key, project verifier key and the
new device secret key. The oneID verifier key can be downloaded
from the `oneID developer console`_.

You can print out your project verifier key by adding a snippet to the previous code
example.

.. code-block:: python

   import base64
   project_verifier = base64.b64encode(project_key.public_key_der)
   print(project_verifier)

If you can SSH into your IoT device, you can do the same thing that we did with the server
and copy over the device identity secret key. Since the oneID and project verifier keys
are static for all devices in a project, we can hard them in code.

.. code-block:: console

    $ scp /Users/me/secret/device_secret.pem edison@10.1.2.3:/home/root/device_secret.pem

Now that we have the message that was sent to the IoT device, let's check the message's authenticity
by verifying the digital signatures.

.. code-block:: python

   import base64
   import json
   from oneid import keychain

   # Verifier provided by oneID
   oneid_verifier = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE21O6XdFYPzGLhjlvBPpK' \
                    'X7qOKL/4pSPRwIv8B8R6pUsW82oHMwFKPZDa+K9sN3k7b3+BLl2gvWRA' \
                    'vcVwi0QqRw=='

   project_verifier = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBhZyiOPVT35tPbLTxX' \
                      'ERM84dDRPDmNbOkmm7kxnESi3r5aAl7Ew9PkYc6qK13Wet6ZNweWnP' \
                      'Q3XfvD1h6c1KMw=='

   oneid_keypair = keychain.Keypair.from_public_der(base64.b64decode(oneid_verifier))

   project_keypair = keychain.Keypair.from_public_der(base64.b64decode(project_verifier))

   # Deserialize the authenticated message
   data = json.loads(authenticated_msg)

   # Verify Message
   oneid_keypair.verify(data.get('payload').encode('utf-8'), data.get('oneid_signature'))
   project_keypair.verify(data.get('payload').encode('utf-8'), data.get('project_signature'))

   header_b64, claims_b64 = data.get('payload')

   # Deserialize the claims
   claims_data = base64.b64decode(claims_b64)
   claims = json.loads(claims_data)

   # Finally print the authenticated message
   print(claims.get('message'))

If either of the keypairs fail to authenticate the message, an ``InvalidSignature`` exception will be raised.


.. _oneID developer account: https://developer.oneid.com/console
.. _oneID developer console: https://developer.oneid.com/console
.. _Redis Quick Start: http://redis.io/topics/quickstart
