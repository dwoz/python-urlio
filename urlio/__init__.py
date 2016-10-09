"""
File system like access to urls
"""
from __future__ import absolute_import
from .path import PathFactory
from .url import UrlFactory

__version__ = '0.6.0'

Url = UrlFactory()
Path = PathFactory()
