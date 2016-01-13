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

   $ pip isntall oneid-cli



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

You will be given two project keys. The first is a **SECRET** key.

.. danger::
  SAVE THE PROJECT SECRET KEY IN A SAFE PLACE.
  If you lose this key, you will lose your ability to send authenticated messages
  to your devices.

The second project key will be given to all your edge devices and used
to verify messages sent from a server.

.. note::

  The project public key can easily be re-generated as long as you
  have the corresponding secret the key


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

In python, we're just going to hardcode the path to these keys for quick access.

.. code-block:: python

    import time
    import json
    import base64

    from oneid.token import Token
    from oneid.session import Session

    # Secret keys we downloaded from oneID Developer Portal
    server_secret_key_path = '/home/www/server_key.pem'
    project_secret_key_path = '/home/www/project_key.pem'

    # Unique Server id,
    # we generated ours from uuid.uuid4()
    server_id = 'c75a1dfe-b468-4820-9114-2c94c7e092dc'

    # using the server's private key that was downloaded
    # from the oneID Developer Portal, sign the payload
    server_token = Token.load_secret_pem(server_secret_key_path)
    server_token.identity = server_id

    session = Session(server_token, project_id='<insert project id from oneID>')

    auth_response = session.authenticate.server(server_id=server_id)

    # Strip oneID's signature off the response
    # *oneID responds with the same payload, but signs with its secret key
    oneid_signature = auth_response.split('.')[-1]

    # WARNING, if you change anything in the claims here,
    # verification will fail
    alg, claims = auth_response.split('.')[:2]
    payload = '{alg}.{claims}'.format(alg=alg, claims=claims)

    # sign the payload with the project token
    project_token = Token.load_secret_pem(project_secret_key_path)
    project_signature = project_token.sign(payload)

    # create a message with both signatures
    authenticated_msg = {'message': payload,
                         'project_sig': project_signature,
                         'oneid_sig': oneid_signature}

The final step is to send the two-factor ``authenticated_msg``
to the IoT device. You can use any network protocol you want,
or a messaging protocol such as MQTT, RabbitMQ, Redis etc.

I'm a fan of Redis, and Redis is incredibly simple to use.
Setting up a Redis server is out of the scope of this tutorial,
but you can use this `Redis Quick Start`_.

After installing Redis, you need to start the Redis server

.. code-block:: console

    $ redis-server


You will also need the Redis Python client library.

.. code-block:: console

    $ pip install redis

With redis now installed, let's create a publisher and publish the ``authenticated_msg``

.. code-block:: python

    import redis

    # create a redis connection to send the
    redis_conn = redis.StrictRedis(host='localhost', port=6379, db=0)

    # publish authenticated message to the IoT device
    redis_conn.publish('edge_device:firmware_update', json.dumps(authenticated_msg))


IoT Device
~~~~~~~~~~
Just like we did with the server we need to start with provisioning our IoT device.

.. code-block:: console

    $ oneid-cli provision --name "my edge device" --type device


Now we need to copy over the oneID public key, project public key and the
new device secret key. The oneID public key can be downloaded
from the `oneID developer console`_.

If you can SSH into your IoT device, you can do the same thing as we did with the server.

.. code-block:: console

    $ scp /Users/me/secret/device_secret.pem edison@10.1.2.3:/home/root/device_secret.pem
    $ scp /Users/me/secret/oneid_pub.pem edison@10.1.2.3:/home/root/oneid_pub.pem
    $ scp /Users/me/secret/project_pub.pem edison@10.1.2.3:/home/root/project_pub.pem

In the final server step, we published a message through Redis.
To receive that message, we're going to setup our IoT device as a subscriber.

.. code-block:: python

   import redis

    # create a redis connection to send the
    redis_conn = redis.StrictRedis(host='<redis ip address>', port=6379, db=0)
    redis_sub = redis_conn.pubsub(ignore_subscribe_messages=True)
    redis_sub.subscribe('edge_device:firmware_update')

    # Get the message published
    payload = redis_sub.get_message()


.. note::
    ``redis_sub.get_message()`` only returns a single message. If you want the device to
    listen forever for new messages, you will need to wrap ``get_message()`` in a ``while True`` block.

Now that we have the message that was sent to the IoT device, let's check the message's authenticity
by verifying the digital signatures.

.. code-block:: python

   from oneid import keychain

   # Load tokens into memory
   oneID_key_path = '/home/root/oneid_pub.pem'
   oneID_token = keychain.Token.from_public_key(path=oneID_key_path)

   project_key_path = '/home/root/project_pub.pem'
   project_token = keychain.Token.from_public_key(path=project_key_path)

   # Verify Message
   oneID_token.verify(payload.get('message'), payload.get('oneid_sig'))
   project_token.verify(payload.get('message'), payload.get('project_sig'))

If either of the tokens fail to authenticate the message, an ``InvalidSignature`` exception will be raised.


.. _oneID developer account: https://developer.oneid.com/console
.. _oneID developer console: https://developer.oneid.com/console
.. _Redis Quick Start: http://redis.io/topics/quickstart
