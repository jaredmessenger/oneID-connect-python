Installation for Ubuntu
=======================
oneID-py depends on two external libraries, cryptography.io and openSSL.
cryptography.io is a library that exposes cryptographic primitives from openSSL.

``oneid-connect`` should build easily on most Linux distributions that have a C compiler,
openSSL headers and the ``libffi`` libraries.

.. code-block:: console

    $ sudo apt-get install build-essential libssl-dev libffi-dev python-dev

You should now be able to install ``oneid-connect`` with the usual

.. code-block:: console

    $ pip install oneid-connect


