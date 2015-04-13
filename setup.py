#!/usr/bin/env python

from distutils.core import setup
from traxcommon import VERSION

setup(
    name='traxcommon',
    version='.'.join(VERSION),
    description='Trax common python functionality',
    author='Trax Technologies, Inc',
    author_email='devops@traxtech.com',
    url='https://github.com/TraxTechnologies/python-common',
    packages=['traxcommon'],
)
