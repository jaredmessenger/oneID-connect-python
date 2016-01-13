.. oneID-connect documentation master file, created by
   sphinx-quickstart on Mon Nov  2 17:57:31 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

oneID-connect
=============
``oneID-connect`` is a Python authentication framework for the Internet of Things (IoT), servers and end-users.
By sending messages with digital signatures, you can authenticate the origin of the message and
ensure the message hasn't been tampered with. ``oneID-connect`` makes it simple for projects that need to
send authenticated messages and verify the authentication of messages.

``oneID-connect`` can be installed on IoT devices and servers that support python 2.7.
``oneID-connect`` depends on two external libraries: the cryptography.io python package and openSSL.



Introduction
------------
oneID has been ridding the internet of user names and passwords for several years now. We've recently
decided to expand our platform to include IoT devices. At oneID, we believe passwords are cumbersome
and incredibly insecure. Trying to type a user name and password on a device that's smaller than your
finger isn't ideal and incredibly frustrating. So oneID has created a secure two-factor mutual authentication
platform that securely connects users to their IoT devices, while enabling product servers to securely send firmware updates
to those same IoT devices. We do this using state of the art `Elliptical Curve cryptography`_.

Installation
~~~~~~~~~~~~

.. toctree::
   :maxdepth: 3

   installation/index

Tutorials
~~~~~~~~~

.. toctree::
   :maxdepth: 2

   tutorials/index

API
~~~

.. toctree::
   :maxdepth: 2

   api/index

Contributing
~~~~~~~~~~~~

.. toctree::
   :maxdepth: 2

   contributing/index


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _Elliptical Curve cryptography: https://en.wikipedia.org/wiki/Elliptic_curve_cryptography