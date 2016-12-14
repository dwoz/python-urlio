"""
Access Universal Resource Locators
"""
from __future__ import absolute_import, unicode_literals
import io
import os
import time

import boto3
from smb.SMBConnection import OperationFailure
from .smb_ext import storeFileFromOffset
from .dfs import default_find_dfs_share
from .path import (
    SMBPath, LocalPath, CLIENTNAME, SMB_USER, SMB_PASS, get_smb_connection
)
from .base import BasicIO, Uri


class UrlFactory(object):

    def __call__(self, uri, mode='r'):
        "Path factory that accepts URI's instead of paths"
        uri = Uri(uri)
        if uri.protocol in ['cifs', 'smb']:
            return SMBUrl(str(uri))
        elif uri.protocol in ['s3']:
            return S3Url(str(uri))
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
            raise Exception('wrong protocol type: {}'.format(uri.protocol))
        if not uri.path:
            raise Exception()
        self.url = str(uri)
        self.__fp = None
        self._mode = mode

    @property
    def fp(self):
        if not hasattr(self, '_fp') or not self._fp or self._fp.closed:
            dirname = os.path.dirname(Uri(self.url).path)
            self._fp = io.open(Uri(self.url).path, self.mode)
        return self._fp

    @property
    def mode(self):
        return self._mode

    def seek(self, index, *args):
        self.fp.seek(index, *args)

    def tell(self):
        return self.fp.tell()

    def read(self, size=-1):
        if size and size != -1:
            return self.fp.read(size)
        else:
            return self.fp.read()

    def write(self, data):
        dirname = os.path.dirname(Uri(self.url).path)
        if dirname and not os.path.exists(dirname):
            os.makedirs(dirname)
        self.fp.write(data)

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
            p = LocalUrl(p.static_join(p.url, joinname), **kwargs)
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
        self._is_direct_tcp = None

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

    def tell(self):
        return self._index

    def seek(self, index, *args):
        self._index = index

    def read(self, size=-1, conn=None):
        if size is None:
            size = -1
        if conn is None:
            conn = self.get_connection()
        fp = io.BytesIO()
        conn.retrieveFileFromOffset(
            self.share, self.relpath, fp, self._index, size
        )
        self._index = self._index + fp.tell()
        fp.seek(0)
        return fp.read()

    def get_connection(self):
        from socket import error
        if not self._conn:
            if self._is_direct_tcp is None:
                try:
                    self._conn = get_smb_connection(
                        self.server_name, self.domain, self.user, self.password,
                        timeout=self.timeout, is_direct_tcp = True
                    )
                    self._is_direct_tcp = True
                except error as e:
                    if e.errno != 61 and e.errno != 104:
                        raise
                    self._conn = get_smb_connection(
                        self.server_name, self.domain, self.user, self.password,
                        timeout=self.timeout, is_direct_tcp = False
                    )
                    self._is_direct_tcp = False
            else:
                self._conn = get_smb_connection(
                    self.server_name, self.domain, self.user, self.password,
                    timeout=self.timeout, is_direct_tcp=self._is_direct_tcp
                )

            self._conn.timestamp = time.time()
        elif time.time() - self.MAX_CONNECTION_TIME > self._conn.timestamp:
            self._conn = get_smb_connection(
                self.server_name, self.domain, self.user, self.password,
                timeout=self.timeout, is_direct_tcp=self._is_direct_tcp
            )
            self._conn.timestamp = time.time()
        return self._conn

    def exists(self, relpath=None):
        conn = self.get_connection()
        try:
            stat = conn.getAttributes(self.share, self.relpath)
        except OperationFailure:
            return False
        return stat != None

    def makedirs(self, relpath=None, is_dir=False, exist_ok=False):
        if not relpath:
            relpath = self.relpath
        c = self.get_connection()
        if is_dir:
            dirs = relpath.split('\\')
        else:
            dirs = relpath.split('\\')[:-1]
        path = ''
        if self.WRITELOCK:
            self.WRITELOCK.acquire(self.server_name, self.share, self.relpath)
        try:
            for a in dirs:
                path = '{0}\\{1}'.format(path.strip('\\'), a.strip('\\'))
                if path != self.relpath or exist_ok:
                    try:
                        c.listPath(self.share, path, timeout=self.timeout)
                    except smb.smb_structs.OperationFailure as e:
                        pass
                    else:
                        continue
                c.createDirectory(self.share, path)
        finally:
            if self.WRITELOCK:
                self.WRITELOCK.release(self.server_name, self.share, self.relpath)

    def write(self, fp):
        if not hasattr(fp, 'read'):
            fp = io.BytesIO(fp)
        if self.mode == 'r':
            raise Exception("File not open for writing")
        if self.WRITELOCK:
            self.WRITELOCK.acquire(self.server_name, self.share, self.relpath)
        try:
            conn = self.get_connection()
            storeFileFromOffset(conn, self.share, self.relpath, fp, offset=self._index, timeout=self.timeout)
            fp.seek(0)
            self._index = self._index + len(fp.read())
        finally:
            if self.WRITELOCK:
                self.WRITELOCK.release(self.server_name, self.share, self.relpath)

    def files(self, glob='*', limit=0, offset=0, recurse=False):
        return self.ls(
            glob=glob, return_dirs=False, limit=limit, offset=offset,
            recurse=recurse
        )

    def filenames(self, glob='*', limit=0, offset=0, recurse=False):
        return self.ls_names(
            glob=glob, return_dirs=False, limit=limit, offset=offset,
            recurse=recurse,
        )

    def dirs(self, glob='*', limit=0, offset=0, recurse=False):
        return self.ls(
            glob=glob,
            limit=limit,
            offset=offset,
            recurse=recurse,
            return_files=False
        )

    def dirnames(self, glob='*', limit=0, offset=0, recurse=False):
        return self.ls_names(
            glob=glob,
            limit=limit,
            offset=offset,
            recurse=recurse,
            return_files=False
        )

    def _walk(self):
        dirs = []
        files = []
        for i in self.ls():
            if i.isdir():
                dirs.append(i)
            else:
                files.append(i)
        return dirs, files

    def walk(self, top_down=False):
        dirs, files = self._walk()
        if top_down:
            for x in dirs:
                for _ in x.walk(top_down=top_down):
                    yield _
        yield self, dirs, files
        if top_down:
            return
        for x in dirs:
            for _ in x.walk(top_down=top_down):
                yield _

    def close(self):
        self.get_connection().close()

    def ls(
            self, glob='*', limit=0, offset=0, recurse=False,
            return_files=True, return_dirs=True, _done=0, _at=-1
        ):
        """
        List a directory and return the names of the files and directories.
        """
        conn = self.get_connection()
        paths = []
        if not return_files and not return_dirs:
            raise Exception("At lest one return_files or return_dirs must be true")
        paths = iter_listPath(
            conn,
            self.share,
            self.relpath,
            pattern=glob,
            limit=0,
            timeout=self.timeout,
            begin_at=0,
            ignore=self.ignore_filenames,
        )
        for a in paths:
            _at += 1
            if _at < offset:
                continue
            if limit > 0 and _done >= limit:
                raise StopIteration
            if a.isDirectory:
                p = self.join(a.filename, _attrs=a)
                if return_dirs:
                    yield p
                    _done += 1
                if recurse:
                    for _ in p.ls(glob, limit, offset, recurse, return_files,
                        return_dirs, _done, _at):
                        yield _
                        _done += 1
            elif return_files:
                yield SMBPath(self.path).join(
                    a.filename, _attrs=a
                )
                _done += 1

    def recurse_files(self, glob='*', limit=0, offset=0):
        return self.filenames(
            glob=glob, recurse=True, limit=limit, offset=offset,
        )

    def recurse(self, glob='*', limit=0, offset=0):
        return self.ls_names(
            glob=glob, limit=limit, offset=offset, recurse=True
        )

    def ls_names(
            self, glob='*', limit=0, offset=0, recurse=False, return_files=True,
            return_dirs=True
        ):
        """
        List a directory and return the names of the files and directories.
        """
        for a in self.ls(
                glob=glob, limit=limit, offset=offset, recurse=recurse,
                return_files=return_files, return_dirs=return_dirs,
            ):
            yield a.path

    def remove(self):
        conn = self.get_connection()
        if self.WRITELOCK:
            self.WRITELOCK.acquire(self.server_name, self.share, self.relpath)
        if self.isdir():
            try:
                conn.deleteDirectory(self.share, self.relpath)
            finally:
                if self.WRITELOCK:
                    self.WRITELOCK.release(self.server_name,  self.share, self.relpath)
            return
        try:
            conn.deleteFiles(self.share, self.relpath)
        finally:
            if self.WRITELOCK:
                self.WRITELOCK.release(self.server_name,  self.share, self.relpath)

    @staticmethod
    def _dirname(inpath):
        return smb_dirname(inpath)

    @property
    def _attrs(self):
        if not self.__attrs:
            conn = self.get_connection()
            self.__attrs = conn.getAttributes(self.share, self.relpath)
        return self.__attrs

    @_attrs.setter
    def _attrs(self, attrs):
        self.__attrs = attrs

    @property
    def atime(self):
        return getFiletime(self._attrs.last_access_time)

    @property
    def mtime(self):
        return getFiletime(self._attrs.last_write_time)

    @property
    def ctime(self):
        return getFiletime(self._attrs.create_time)

    @property
    def size(self):
        return self._attrs.file_size

    def stat(self):
        # dir(self._attrs) == ['__doc__', '__init__', '__module__',
        # '__unicode__', 'alloc_size', 'create_time', 'file_attributes',
        # 'file_size', 'filename', 'isDirectory', 'isReadOnly',
        # 'last_access_time', 'last_attr_change_time',
        # 'last_write_time', 'short_name']
        return {
           'size': self._attrs.file_size,
           'atime': getFiletime(self._attrs.last_access_time),
           'mtime': getFiletime(self._attrs.last_write_time),
           'ctime': getFiletime(self._attrs.create_time),
        }

    @property
    def dirname(self):
        return smb_dirname(self.path)

    @property
    def rel_dirname(self):
        return smb_dirname(self.relpath)

    @property
    def basename(self):
        return smb_basename(self.path)

    @property
    def rel_basename(self):
        return smb_basename(self.relpath)

    def join(self, *joins, **kwargs):
        p = self
        for joinname in joins:
            p = SMBPath(p.static_join(p.path, joinname), **kwargs)
        return p

    @staticmethod
    def static_join(dirname, basename):
        return u"{0}\\{1}".format(
            dirname.rstrip('\\'),
            basename.lstrip('\\')
        )

    def readline(self):
        size = 1024
        start_pos = self.tell()
        while True:
            chunk = self.read(size)
            if not chunk:
                break
            if chunk.find('\n') != -1:
                break
        if chunk.find('\n') == -1:
            return
        line = chunk[:chunk.find('\n') + 1]
        self.seek(start_pos + len(line))
        return line

    def readlines(self):
        line = self.readline()
        while line:
            yield line
            line = self.readline()

    def isdir(self):
        return self._attrs.isDirectory

    def rename(self, newname):
        newp = SMBPath(newname)
        if newp.server_name != self.server_name or newp.share != self.share:
            raise Exception("Can only rename on the same server and share")
        c = self.get_connection()
        c.rename(self.share, self.relpath, newp.relpath)
        self.relpath = newp.relpath

    def rmtree(self):
        for _, dirs, files in self.walk(top_down=True):
            for d in dirs:
                if d.exists():
                    d.remove()
            for f in files:
                f.remove()
            _.remove()


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
