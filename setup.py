#!/usr/bin/env python

from distutils.core import setup
from traxcommon import VERSION

setup(
    name='traxcommon',
    version='.'.join([str(i) for i in VERSION]),
    description='Trax common python functionality',
    author='Trax Technologies, Inc',
    author_email='devops@traxtech.com',
    url='https://github.com/TraxTechnologies/python-common',
    packages=['traxcommon'],
    install_requires=[
        'pysmb==1.1.13',
        'requests>=2.0.0',
        'python-magic>=0.4.6',
        'boto==2.3.0',
        'repoze.lru',
    ],
)
