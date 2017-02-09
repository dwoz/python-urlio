"""
File system like access to urls
"""
from __future__ import absolute_import
from .path import PathFactory, set_smb_username, set_smb_password
from .url import UrlFactory

__version__ = '0.6.4'

Url = UrlFactory()
Path = PathFactory()
