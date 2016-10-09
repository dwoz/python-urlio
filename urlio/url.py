"""
Access Universal Resource Locators
"""
from __future__ import absolute_import
import io
import os

import boto3

from .path import (
    SMBPath, LocalPath, CLIENTNAME, default_find_dfs_share,
    SMB_USER, SMB_PASS
)
from .baseio import BasicIO
from .uri import Uri


class UrlFactory(object):

    def __call__(self, uri, mode='r'):
        "Path factory that accepts URI's instead of paths"
        uri = Uri(uri)
        if uri.protocol in ['cifs', 'smb']:
            return SMBUrl(str(uri))
        return LocalUrl(str(uri))


Url = UrlFactory()


def uri_to_path(uri):
    if not isinstance(uri, Uri):
        uri = Uri(uri)
    return uri.path

class LocalUrl(BasicIO):

    def __init__(self, uri, mode='r'):
        uri = Uri(uri)
        if uri.protocol != 'file':
            raise Exception('wrong protocol type: {}'.format(uri.protcol))
        if not uri.path:
            raise Exception()
        self.uri = Uri(uri)
        self.__fp = None
        self._mode = mode

    @property
    def fp(self):
        if not hasattr(self, '_fp') or not self._fp or self._fp.closed:
            dirname = os.path.dirname(self.uri.path)
            self._fp = io.open(self.uri.path, self.mode)
        return self._fp

    @property
    def mode(self):
        return self._mode

    @property
    def uri(self):
        """
        Override LocalPath's uri property to make it settable
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        self._uri = uri

    def seek(self, index, *args):
        self.fp.seek(index, *args)

    def tell(self):
        return self.fp.tell()

    def read(self, size=-1):
        if size and size != -1:
            return self.fp.read(size)
        else:
            return self.fp.read()

    def write(self, s):
        dirname = os.path.dirname(self.uri.path)
        if dirname and not os.path.exists(dirname):
            os.makedirs(dirname)
        self.fp.write(s)

    def exists(self):
        return os.path.exists(self.path)

    def ls(self, glb='*', limit=0):
        """
        Iterate over path objects for the files and directories in this
        path.
        """
        for a in self.ls_names(glb, limit=limit):
            yield Path(a)

    def ls_names(self, glb='*', limit=0, recurse=False):
        """
        Iterate over the names of files and directories within this
        path.
        """
        if recurse:
            raise Exception("Recursion not implimented")
        n = 0
        for a in libglob.glob(os.path.join(self.path, glb)):
            yield a
            n += 1
            if limit > 0 and n >= limit:
                raise StopIteration

    def isdir(self):
        return os.path.isdir(self.path)

    def filenames(self, glob='*', limit=0, recurse=False):
        """
        Iterate over the names of files (not directories) within this
        path.
        """
        for a in self.ls_names(glob, limit=limit, recurse=recurse):
            if os.path.isfile(a):
                yield a

    def files(self, glob='*', limit=0):
        """
        Iterate over path objects for the files (not directories) within
        this path.
        """
        for a in self.filenames(glob, limit=limit):
            yield Path(a)

    def dirnames(self, glob='*', limit=0):
        for a in self.ls_names(glob, limit=limit):
            if os.path.isdir(a):
                yield a

    def dirs(self, glob='*', limit=0):
        for a in self.dirnames(glob, limit=limit):
            yield Path(a)

    def close(self):
        self.fp.close()

    def remove(self):
        if os.path.isdir(self.path):
            os.removedirs(self.path)
        else:
            self.fp.close()
            os.remove(self.path)

    @property
    def dirname(self):
        if self.path.endswith('/'):
            path = self.path.rstrip('/')
        else:
            path = self.path
        dirname = path.rsplit('/', 1)[0]
        return dirname or '/'

    @property
    def basename(self):
        parts = self.path.rstrip('/').split('/')
        return parts[-1] or '/'

    def join(self, *joins, **kwargs):
        p = self
        for joinname in joins:
            p = LocalPath(p.static_join(p.path, joinname), **kwargs)
        return p

    @staticmethod
    def static_join(dirname, basename):
        return u"{0}/{1}".format(dirname.rstrip('/'), basename.strip('/'))

    def readline(self):
        return self.fp.readline()

    def readlines(self):
        return self.fp.readlines()

    @property
    def size(self):
        return os.stat(self.path).st_size

    @property
    def ctime(self):
        return datetime.datetime.utcfromtimestamp(os.stat(self.path).st_ctime)

    @property
    def mtime(self):
        return datetime.datetime.utcfromtimestamp(os.stat(self.path).st_mtime)

    @property
    def atime(self):
        return datetime.datetime.utcfromtimestamp(os.stat(self.path).st_atime)

    def makedirs(self, is_dir=False, exist_ok=False):
        if is_dir:
            try:
                os.makedirs(self.path)
            except OSError as exc:
                if exc.errno == errno.EEXIST and os.path.isdir(self.path) and exist_ok:
                    return
                raise
        else:
            try:
                os.makedirs(self.basename)
            except OSError as exc:
                if exc.errno == errno.EEXIST and os.path.isdir(self.basename) and exist_ok:
                    return
                raise

    def stat(self):
        return {
            'size': self.size,
            'atime': self.atime,
            'mtime': self.mtime,
            'ctime': self.ctime,
        }

    def rmtree(self):
        shutil.rmtree(self.path)

    def rename(self, newname):
        os.rename(self.path, newname)
        self.path = newname


class SMBUrl(SMBPath, BasicIO):

    def __init__(
            self, uri, mode='r', user=None, password=None, api=None,
            clientname=CLIENTNAME, find_dfs_share=None, write_lock=None,
            timeout=120, _attrs=None,
            ):

        self._orig_uri = uri
        self.uri = Uri(uri)
        path = u'\\\\{}{}'.format(self.uri.host, self.uri.path.replace('/', '\\'))
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

    def __repr__(self):
        return '<SMBUrl({}, mode={}) at {}>'.format(
            repr(str(self.uri)), repr(str(self.mode)), hex(id(self))
        )

    @property
    def uri(self):
        """
        Override SMBPath's uri property to make it settable
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        self._uri = uri


class _S3Upload(object):

    def __init__(self, mp, parts=None):
        self.mp = mp
        self.parts = parts or []
        self._part = None

    def part(self):
        if not self._part:
            self._part = self.mp.Part(len(self.parts) + 1)
        return self._part


class S3Url(BasicIO):

    def __init__(self, uri, mode='rb'):
        uri = Uri(uri)
        if not uri.protocol == 's3':
            raise Exception()
        self._orig_uri = uri
        self.uri = Uri(uri)
        self._access_key = ''
        self._access_key_id = ''
        self._upload = None

    def _bucket(self):
        session = boto3.Session(
            aws_access_key_id=self._access_key_id,
            aws_secret_access_key=self._access_key,
        )
        s3 = session.resource('s3')
        return s3.Bucket(self.uri.host)

    def _key(self):
        return self._bucket().Object(self.uri.path)

    def write(self, chunk):
        src = io.BytesIO(chunk)
        parts = []
        mp = self._key().initiate_multipart_upload(
            Metadata={'location': self.uri.path.lstrip('/')}
        )
        while True:
            chunk = src.read(8 * 1024 * 1024)
            if not chunk:
                break
            part_num = len(parts) + 1
            part = mp.Part(part_num)
            response = part.upload(Body=chunk)
            parts.append({'ETag': response['ETag'], 'PartNumber': part_num})
        mp.complete(MultipartUpload={"Parts": parts})

    def read(self):
        fb = io.BytesIO()
        key = self._key()
        resp = key.get()
        return resp['Body'].read()

    def close(self):
        """No op close method"""
        pass
