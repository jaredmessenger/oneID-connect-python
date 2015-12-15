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

oneID-py can be installed on IoT devices and servers that support python 2.7.
oneID-py depends on two external libraries: the cryptography.io python package and openSSL.

.. toctree::
   :maxdepth: 2
   :hidden:

   installation/device/intel-edison
   installation/server/ubuntu
   installation/server/osx
   api/token
   tutorials/hello-world
   tutorials/telemetry-data
   tutorials/firmware-update

Introduction
------------
oneID has been ridding the internet of user names and passwords for several years now. We've recently
decided to expand our platform to include IoT devices. At oneID, we believe passwords are cumbersome
and incredibly insecure. Trying to type a user name and password on a device that's smaller than your
finger isn't ideal and incredibly frustrating. So oneID has created a secure two-factor mutual authentication
platform that securely connects users to their IoT devices, while enabling product servers to securely send firmware updates
to those same IoT devices. We do this using state of the art `Elliptical Curve cryptography`_.

Installation
------------
- :doc:`installation/device/intel-edison`
- :doc:`installation/server/ubuntu`
- :doc:`installation/server/osx`


API
----
- :doc:`api/token`


Tutorials
---------
- :doc:`tutorials/hello-world`
- :doc:`tutorials/telemetry-data`
- :doc:`tutorials/firmware-update`


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _Elliptical Curve cryptography: https://en.wikipedia.org/wiki/Elliptic_curve_cryptography