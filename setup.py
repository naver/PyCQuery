from setuptools.command.test import test as test_command
from setuptools import setup
import sys
import os
import pycquery

class PyTest(test_command):
    def finalize_options(self):
        test_command.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)


setup(
    name='PyCQuery',
    version=pycquery.__version__,
    description='Python interface to Hive with pure-python Kerberos support',
    url='https://github.com/naver/PyCQuery',
    author='NAVER Corp.',
    license='Apache License, Version 2.0',
    package_dir={
        'pycquery': os.path.join(os.path.abspath(os.path.dirname(__file__)), 'pycquery'),
        'TCLIService': os.path.join(os.path.abspath(os.path.dirname(__file__)), 'TCLIService'),
        'pycquery_krb': os.path.join(os.path.abspath(os.path.dirname(__file__)), 'pycquery_krb'),
        'pycquery_krb/common': os.path.join(os.path.abspath(os.path.dirname(__file__)),
            'pycquery_krb', 'common'),
        'pycquery_krb/crypto': os.path.join(os.path.abspath(os.path.dirname(__file__)),
            'pycquery_krb', 'crypto'),
        'pycquery_krb/crypto/AES': os.path.join(os.path.abspath(os.path.dirname(__file__)),
            'pycquery_krb', 'crypto', 'AES'),
        'pycquery_krb/crypto/DES': os.path.join(os.path.abspath(os.path.dirname(__file__)),
            'pycquery_krb', 'crypto', 'DES'),
        'pycquery_krb/crypto/PBKDF2': os.path.join(os.path.abspath(os.path.dirname(__file__)),
            'pycquery_krb', 'crypto', 'PBKDF2'),
        'pycquery_krb/crypto/RC4': os.path.join(os.path.abspath(os.path.dirname(__file__)),
            'pycquery_krb', 'crypto', 'RC4'),
        'pycquery_krb/gssapi': os.path.join(os.path.abspath(os.path.dirname(__file__)),
            'pycquery_krb', 'gssapi'),
        'pycquery_krb/network': os.path.join(os.path.abspath(os.path.dirname(__file__)),
            'pycquery_krb', 'network'),
        'pycquery_krb/protocol': os.path.join(os.path.abspath(os.path.dirname(__file__)),
            'pycquery_krb', 'protocol'),
    },
    packages=['pycquery', 'TCLIService',
              'pycquery_krb', 'pycquery_krb/common', 'pycquery_krb/crypto',
              'pycquery_krb/gssapi', 'pycquery_krb/network', 'pycquery_krb/protocol',
              'pycquery_krb/crypto/AES', 'pycquery_krb/crypto/DES',
              'pycquery_krb/crypto/PBKDF2', 'pycquery_krb/crypto/RC4'],
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    python_requires='>=3.6',
    install_requires=[
        'future>=0.18.2',
        'python-dateutil>=2.8.1',
        'kazoo>=2.8.0',
        'requests>=2.25.1',
        'thrift>=0.13.0',
        'asn1crypto>=1.4.0',
        'asysocks>=0.1.0',
        'pyasn1>=0.4.8',
        'pytimeparse>=1.1.8'
    ],
    tests_require=[
        'mock>=1.0.0',
        'pytest',
        'pytest-cov',
        'kazoo>=2.8.0',
        'requests>=2.25.1',
        'thrift>=0.13.0',
        'asn1crypto>=1.4.0',
        'asysocks>=0.1.0',
        'pyasn1>=0.4.8',
        'pytimeparse>=1.1.8'
    ],
    cmdclass={'test': PyTest},
    zip_safe=False,
)
