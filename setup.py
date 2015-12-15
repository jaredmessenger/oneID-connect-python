import os

from setuptools import setup, find_packages
from codecs import open

base_dir = os.path.dirname(__file__)
src_dir = os.path.join(base_dir, "src")


about = {}
with open(os.path.join(src_dir, "oneid", "__about__.py")) as f:
    exec(f.read(), about)

with open(os.path.join(base_dir, "README.rst")) as f:
    long_description = f.read()

setup(
    name=about['__title__'],
    version=about['__version__'],
    description=about['__summary__'],
    long_description=long_description,
    url=about['__uri__'],
    author=about['__author__'],
    author_email=about['__email__'],
    license=about['__license__'],
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