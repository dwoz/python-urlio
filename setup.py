#!/usr/bin/env python

import sys
from setuptools import setup
from setuptools.command.test import test as TestCommand
from traxcommon import VERSION


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


class Tox(TestCommand):
    user_options = [('tox-args=', 'a', "Arguments to pass to tox")]
    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.tox_args = None
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True
    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import tox
        import shlex
        args = self.tox_args
        if args:
            args = shlex.split(self.tox_args)
        tox.cmdline(args=args)


setup(
    name='traxcommon',
    version='.'.join([str(i) for i in VERSION]),
    description='Trax common python functionality',
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
    ],
    author='Trax Technologies, Inc',
    author_email='devops@traxtech.com',
    url='https://github.com/TraxTechnologies/python-common',
    packages=['traxcommon'],
    install_requires=install_requires,
    tests_require=['tox'],
    cmdclass = {'test': Tox},
)
