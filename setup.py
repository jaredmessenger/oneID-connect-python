from setuptools import setup, find_packages
from codecs import open
from os import path

current_dir = path.abspath(path.dirname(__file__))

with open(path.join(current_dir, 'DESCRIPTION.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='oneid-connect',
    version='0.0.1',
    long_description=long_description,
    url='https://github.com',
    author='oneID',
    author_email='support@oneID.com',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: BSD",
        "Operating System :: POSIX :: Linux",
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 2.7',
    ],

    keywords='oneID IoT Authentication',
    package_dir={"": "src"},
    packages=find_packages(where='src',
                           exclude=['contrib', 'docs', 'tests*',
                                    'venv', 'example*', '*egg-info',
                                    '.gitignore']),
    install_requires=['cryptography'],
)