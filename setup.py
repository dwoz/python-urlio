#!/usr/bin/env python

import sys
from setuptools import setup
from setuptools.command.test import test as TestCommand

USE_TOX=False


with open('requirements.txt') as fp:
    install_requires = []
    for s in fp.readlines():
        s = s.strip()
        if s.startswith('-e'):
            l = s.split('#')[1].split('&')
            for a in l:
                if a.startswith('egg'):
                    b = a.lstrip('egg=')
        else:
            b = s
        install_requires.append(b)


class TestCmd(TestCommand):
    user_options = [('test-args=', 'a', "Arguments to pass to test runner")]
    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.tox_args = None
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True
    def run_tests(self):
        if USE_TOX:
            #import here, cause outside the eggs aren't loaded
            import tox
            import shlex
            args = self.tox_args
            if args:
                args = shlex.split(self.test_args)
            tox.cmdline(args=args)
        else:
            import pytest
            errno = pytest.main(self.test_args)
            sys.exit(errno)

    @classmethod
    def tests_require(cls):
        if USE_TOX:
            return ['tox==1.8.0']
        return [
            'pytest>=2.8.5'
            'pytest-cov==1.8.0',
        ]


setup(
    name='urlio',
    version='0.6.0',
    description='Filesystem like access to urls',
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
    ],
    author='Trax Technologies, Inc',
    author_email='devops@traxtech.com',
    url='https://github.com/TraxTechnologies/python-urlio',
    packages=['urlio'],
    install_requires=[
        'pysmb==1.1.13',
        'dnspython>=1.12.0',
        'requests>=2.0.0',
        'repoze.lru==0.6',
    ],
    tests_require=TestCmd.tests_require(),
    cmdclass = {'test': TestCmd},
)
