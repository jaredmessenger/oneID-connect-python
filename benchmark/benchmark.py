#!/usr/bin/env python3

import os
import time
import argparse
import platform
import base64
from contextlib import contextmanager

import logging

import oneid

logger = logging.getLogger('__undefined__')


def main():
    parser = argparse.ArgumentParser(description='Run specific benchmark for oneID-connect library')
    parser.add_argument('-d', '--debug',
                        choices=['NONE', 'INFO', 'DEBUG', 'WARNING', 'ERROR'],
                        default='NONE',
                        help='Specify level of debug output (default: %(default)s)'
                        )
    parser.add_argument('-i', '--environment',
                        action='store_true',
                        help='Display runtime environment description'
                        )
    parser.add_argument('-a', '--aes-keys',
                        action='store_true',
                        help='Generate AES keys'
                        )
    parser.add_argument('-S', '--symmetric',
                        action='store_true',
                        help='Encrypt and decrypt random bytes'
                        )
    parser.add_argument('-E', '--ecdsa-key',
                        action='store_true',
                        help='Generate ECDSA keys'
                        )
    parser.add_argument('-A', '--asymmetric',
                        action='store_true',
                        help='Sign and verify signatures'
                        )
    parser.add_argument('-J', '--jwt',
                        action='store_true',
                        help='Create and verify JWTs'
                        )
    parser.add_argument('-s', '--data-size',
                        type=int,
                        default=256,
                        help='Number of bytes for operations on random data (default: %(default)s)'
                        )
    parser.add_argument('-n', '--count',
                        type=int,
                        default=1000,
                        help='Number of operations to perform (default: %(default)s)'
                        )

    args = parser.parse_args()

    set_logging_level(args.debug)
    logger = logging.getLogger('oneID-connect/benchmark')

    logger.debug('args=%s', args)

    if (args.environment):
        show_environment()
    if args.aes_keys:
        run_aes_keys_tasks(args.count)
    if args.symmetric:
        run_symmetric_tasks(args.data_size, args.count)
    if args.ecdsa_key:
        run_ecdsa_key_tasks(args.count)
    if args.asymmetric:
        run_asymmetric_tasks(args.data_size, args.count)
    if args.jwt:
        run_jwt_tasks(args.data_size, args.count)


@contextmanager
def operations_timer(numops, oplabel='operations'):
    start = time.process_time()
    yield
    end = time.process_time()
    delta = end - start
    rate = numops/delta

    print('Completed {numops:,d} {oplabel} in {delta:,.3f} seconds, or {rate:,.2f} {oplabel}/second'
          .format(numops=numops, delta=delta, rate=rate, oplabel=oplabel)
          )


def show_environment():
    print('Environment:')
    print('  {}'.format(platform.platform()))
    print('  {} {}'.format(platform.python_implementation(), platform.python_version()))


def run_aes_keys_tasks(count):
    print('Creating {:,d} AES key(s)'.format(count))

    with operations_timer(count, 'AES keys'):
        for _ in range(count):
            oneid.service.create_aes_key()


def run_symmetric_tasks(data_size, count):
    print('Encrypting/Decrypting {} {}-byte random message(s)'.format(count, data_size))

    key = oneid.service.create_aes_key()
    data = os.urandom(data_size)
    edata = oneid.service.encrypt_attr_value(data, key)

    with operations_timer(count, 'encryptions'):
        for _ in range(count):
            oneid.service.encrypt_attr_value(data, key)

    with operations_timer(count, 'decryptions'):
        for _ in range(count):
            oneid.service.decrypt_attr_value(edata, key)


def run_ecdsa_key_tasks(count):
    print('Creating {:,d} ECDSA key(s)'.format(count))

    with operations_timer(count, 'ECDSA keys'):
        for _ in range(count):
            oneid.service.create_secret_key()


def run_asymmetric_tasks(data_size, count):
    print('Signing/Verifying {:,d} {:,d}-byte random messages'.format(count, data_size))

    keypair = oneid.service.create_secret_key()
    data = os.urandom(data_size)
    sig = keypair.sign(data)

    with operations_timer(count, 'signatures'):
        for _ in range(count):
            keypair.sign(data)

    with operations_timer(count, 'verifies'):
        for _ in range(count):
            if not keypair.verify(data, sig):
                raise RuntimeError('error verifying signature')


def run_jwt_tasks(data_size, count):
    print('Creating/Verifying {:,d} JWTs with {:,d}-byte random payloads'.format(count, data_size))

    keypair = oneid.service.create_secret_key()
    data = {'d': base64.b64encode(os.urandom(data_size)).decode('utf-8')[:data_size]}
    jwt = oneid.service.make_jwt(data, keypair)

    with operations_timer(count, 'creates'):
        for _ in range(count):
            oneid.service.make_jwt(data, keypair)

    with operations_timer(count, 'verifies'):
        for _ in range(count):
            if not oneid.service.verify_jwt(jwt, keypair):
                raise RuntimeError('error verifying jwt')


def set_logging_level(debug_level):
    level = getattr(logging, debug_level.upper(), 100)
    if not isinstance(level, int):
        raise ValueError('Invalid log level: %s' % debug_level)
    logging.basicConfig(level=level,
                        format='%(asctime)-15s %(levelname)-8s [%(name)s:%(lineno)s] %(message)s'
                        )

if __name__ == '__main__':
    main()
