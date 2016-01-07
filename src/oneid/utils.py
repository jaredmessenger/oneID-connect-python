"""
Helpful utility functions
"""

import random
import time
import base64
import re
from datetime import datetime, timedelta
from dateutil import parser, tz
import logging

logger = logging.getLogger(__name__)


def enum(**items):
    """
    Create an enumeration

    :Example:

        Animals = enum(DOG=0, CAT=1)

    :param items: Dict() of keys and integer values
    :return: Enum instance
    """
    return type('Enum', (), items)


def base64url_encode(msg):
    """
    Default b64_encode adds padding, jwt spec removes padding
    :param input:
    :return: base64 en
    """
    encoded_input = base64.urlsafe_b64encode(msg)
    stripped_input = encoded_input.replace('=', '')
    return stripped_input


def base64url_decode(msg):
    """
    JWT spec doesn't allow padding characters. base64url_encode removes them,
    base64url_decode, adds them back in before trying to base64 decode the message

    :param msg: URL safe base64 message
    :return: plain text message
    """
    pad = len(msg) % 4
    if pad > 0:
        msg += '=' * (4 - pad)

    return base64.urlsafe_b64decode(str(msg))


def make_nonce():
    """
    Create a nonce with timestamp included

    :return: nonce
    """
    time_format = '%Y-%m-%dT%H:%M:%SZ'
    time_component = time.strftime(time_format, time.gmtime())
    valid_chars = ''

    # iterate over all the aschii characters for a list of all alpha-numeric characters
    for char_index in range(0, 128):
        if chr(char_index).isalpha() or chr(char_index).isalnum():
            valid_chars += chr(char_index)

    random_str = ''
    random_chr = random.SystemRandom()
    for i in xrange(0, 6):
        random_str += random_chr.choice(valid_chars)

    return '001{time_str}{random_str}'.format(time_str=time_component,
                                              random_str=random_str)


def verify_and_burn_nonce(nonce):
    """
    Ensure that the nonce is correct, less than one hour old,
    and not more than two minutes in the future

    Callers should also store used nonces and reject messages
    with previously-used ones.

    :param nonce: Nonce as created with :func:`~oneid.utils.make_nonce`
    :return: True only if nonce meets validation criteria
    :rtype: bool
    """
    ret = re.match(r'^001[2-9][0-9]{3}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])'
                   r'T([01][0-9]|2[0-3])(:[0-5][0-9]){2}Z[A-Za-z0-9]{6}$', nonce)
    if ret:
        date = parser.parse(nonce[3:-6])
        now = datetime.utcnow().replace(tzinfo=tz.tzutc())
        ret = date < (now + timedelta(minutes=2)) and date > (now + timedelta(hours=-1))

    return ret  # TODO: keep a record (at least for the last hour) of burned nonces
