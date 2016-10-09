"""
File system like access to urls
"""
from __future__ import absolute_import
from .path import PathFactory
from .url import UrlFactory


Url = UrlFactory()
Path = PathFactory()
