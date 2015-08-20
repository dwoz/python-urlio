"""
Access Universal Resource Locators
"""
from path import (
    SMBPath, LocalPath, CLIENTNAME, default_find_dfs_share,
    SMB_USER, SMB_PASS
)
from uri import Uri


def Url(uri, mode='r'):
    "Path factory that accepts URI's instead of paths"
    uri = Uri(uri)
    if uri.protocol in ['cifs', 'smb']:
        return SMBUrl(str(uri))
    return LocalUrl(str(uri))


def uri_to_path(uri):
    if not isinstance(uri, Uri):
        uri = Uri(uri)
    return uri.path

class LocalUrl(LocalPath):

    def __init__(self, uri, mode='r'):
        self._orig_uri = uri
        self.uri = Uri(uri)
        self.__fp = None
        self.mode = mode
        self._set_path(self.uri.path)

    @property
    def uri(self):
        """
        Override LocalPath's uri property to make it settable
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        self._uri = uri

class SMBUrl(SMBPath):

    def __init__(
            self, uri, mode='r', user=None, password=None, api=None,
            clientname=CLIENTNAME, find_dfs_share=None, write_lock=None,
            timeout=120, _attrs=None,
            ):

        self._orig_uri = uri
        self.uri = Uri(uri)
        path = u'\\\\{}{}'.format(self.uri.host, self.uri.path.replace('/', '\\'))
        print path
        self._set_path(path)
        self.find_dfs_share = find_dfs_share or default_find_dfs_share
        server_name, share, domain, relpath = self.find_dfs_share(self.path)
        self.server_name = server_name
        self.share = share
        self.relpath = relpath
        self.domain = domain
        self.user = user or SMB_USER
        self.password = password or SMB_PASS
        self.clientname = clientname
        self.timeout = timeout
        self._index = 0
        self.mode = mode
        self._conn = None
        self.WRITELOCK = write_lock
        self._attrs = _attrs

    @property
    def uri(self):
        """
        Override SMBPath's uri property to make it settable
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        self._uri = uri
