Sending Two-Factor Authenticated Firmware update to IoT Device
==============================================================
Sending a firmware update to all of your devices should always be secure.
The last thing you want is a malicious update sent to your entire fleet of devices.

For this example, we're going to use oneID's two-factor authentication service.
oneID's two-factor authentication service enables you to manage all your servers
and IoT devices. If a server or IoT device has been compromised or taken out of
commission, you can easily revoke it's signing permissions.

Before we begin, you need to create a `developer account on oneID`_

Intro to oneID's Two-Factor Authentication
------------------------------------------
Two-factor means that there will be two signatures for each message.
**BOTH** signatures must be verified before reading the message.
Since there are two signatures that need to be verified on the IoT device,
the IoT device will need to store two public keys. oneID will
provide you with both public keys for the IoT device.

Steps:
~~~~~~
#. Server prepares a message for the IoT device and signs it.
#. Server makes a two-factor authentication request to oneID with the prepared message.
#. oneID verifies the server's identity and responds with oneID's signature of the message
#. Server then re-signs the message with the shared project key.
#. Server sends the message with the two signatures to the IoT device.
#. IoT device verifies **BOTH** signatures.


oneID Developer Portal
----------------------
In the `oneID developer portal`_, create a new project, "My Project". It will
prompt you to download a project key, ``my_project.pem``.

.. rubric:: SAVE THE PROJECT KEY IN A SAFE PLACE.

The project key can't be re-created, it's important to not lose this key. This project key will
need to be shared with all of your servers.

The next step in this tutorial is going to be creating a server,
so let's add a server while we're here and name it "My Server".
It's going to prompt you to download the secret ``my_server.pem`` key.

There is also another key you will need from the `oneID developer portal`_, the
oneID public key. This key will be shared with all of your IoT devices.
It's used to verify oneID's two-factor authentication.

Server
------
The firmware update message we will send to the IoT devices will be very simple.
The message will be a url to the CDN where the firmware update is hosted
and a checksum the IoT device will use to verify the download.

Before we can sign any messages, we need to copy over the secret keys
we downloaded from the oneID developer portal in the previous step.

.. code-block:: console

    $ scp /Users/me/downloads/server_key.pem ubuntu@10.1.2.3:/home/www/server_key.pem
    $ scp /Users/me/downloads/project_key.pem ubuntu@10.1.2.3:/home/www/project_key.pem

In python, we're just going to hardcode the path to these keys for quick access.

.. code-block:: python

    import time
    import json
    import base64

    from oneid.token import Token

    # Secret keys we downloaded from oneID Developer Portal
    server_secret_key_path = '/home/www/server_key.pem'
    project_secret_key_path = '/home/www/project_key.pem'

    server_id = 'unique_server_id'

    header = {'alg': 'ES256', 'typ': 'JWT'}
    message = {'url': 'https://static.oneid.com/firmware/abc',
               'checksum': 'abcd',
               'server': server_name,
               'nonce', 'efgg',
               'timestamp': int(time.time())}

    header_json = json.dumps(header)
    message_json = json.dumps(message)

    payload = '{header}.{message}'.format(header=base64.b64encode(header_json),
                                          message=base64.b64encode(message_json))

    # using the server's private key that was downloaded
    # from the oneID Developer Portal, sign the payload
    server_token = Token()
    server_token.load_secret_pem(server_secret_key_path)
    server_signature = server_token.sign(payload)

    server_jwt = '{payload}.{signature}'.format(payload=payload,
                                                signature=server_signature)

    try:
        # send server_jwt to oneID to receive oneID's signature
        payload, oneid_signature = oneid.authenticate(server_jwt)
    except Exception as e:
        print('Failed to receive oneID\'s authentication')
        print('Error %e' % e.description)
        raise ValueError(e.description)

    # sign the payload with the project token
    project_token = Token()
    project_token.load_secret_pem(project_secret_key_path)
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
----------
First thing we need to do on the IoT device is copy over the oneID public key
from the `oneID developer portal`_.

.. _developer account on oneID: https://developer.oneid.com
.. _oneID developer portal: https://developer.oneid.com
.. _Redis Quick Start: http://redis.io/topics/quickstart