import random
import time
import base64


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
    pad = len(msg) % 4
    if pad > 0:
        msg += '=' * (4 - pad)

    return base64.urlsafe_b64decode(msg)


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

