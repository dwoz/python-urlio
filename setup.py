#!/usr/bin/env python

from distutils.core import setup
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

setup(
    name='traxcommon',
    version='.'.join([str(i) for i in VERSION]),
    description='Trax common python functionality',
    author='Trax Technologies, Inc',
    author_email='devops@traxtech.com',
    url='https://github.com/TraxTechnologies/python-common',
    packages=['traxcommon'],
    install_requires=install_requires
)
