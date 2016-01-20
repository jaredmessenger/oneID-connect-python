Hello World
===========

Here is a simple "hello world" message with a digital signature and verified.

Before we can sign or verify any messages, we first need to create a secret key.

.. code-block:: python

    from oneid import service
    # Directory to save the secret key (should be secure enclave)
    secret_key_pem_path = '/Users/me/my_secret_key.pem'
    service.create_secret_key(output=secret_key_pem_path)

You should now have a secret key pem file that begins with ``-----BEGIN PRIVATE KEY-----``

Now we can create our "hello world" message and sign it.

.. code-block:: python

    from oneid.keychain import Keypair

    message = 'hello world'

    my_key = Keypair.from_secret_pem(path=secret_key_pem_path)
    signature = my_key.sign(message)
    print(signature)

To verify the signature, we need to pass in the message and the signature back into the Token.

..  code-block:: python

    my_key.verify(message, signature)

That's it!

If you want to see what happens if the message has been tampered with, replace ``hello world`` with
something else like ``hello universe``.

.. code-block:: python

    # raises InvalidSignature
    my_key.verify('hello universe', signature)



