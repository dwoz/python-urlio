"""
Interact with filesystems using 'paths' instead of 'urls'. In other words
access things using '\\\\foo\\bar' or '/foo/bar' instead of 'smb://foo/bar' or
'file:///foo/bar'. Local file system and cifs file systems are supported.
"""
from __future__ import absolute_import, unicode_literals
import sys
import json
import errno
import socket
import glob as libglob
import os
import datetime
import requests
import io
import re
import shutil
import time
import smb
import nmb.NetBIOS
import hashlib
import tempfile
import multiprocessing

from smb.SMBConnection import SMBConnection
from smb.SMBConnection import OperationFailure
from smb.smb_constants import *
from smb.smb2_constants import *
import threading
import logging
import repoze.lru
from .smb_ext import iter_listPath, listPath, storeFileFromOffset
from .dfs import default_find_dfs_share as find_dfs_share
from .base import BasicIO
log = logging.getLogger(__name__)

CLIENTNAME = 'FileRouter/{}'.format('/'.join(os.uname()))
SMB_IGNORE_FILENAMES = (
    '.', '..', '$RECYCLE.BIN', '.DS_Store',
)
SMB_USER = os.environ.get('SMBUSER', None)
SMB_PASS = os.environ.get('SMBPASS', None)
if sys.version_info <= (3,):
    EDIDET = re.compile('^.{0,3}ISA.*', re.MULTILINE|re.DOTALL)
    EDIFACTDET = re.compile('^.{0,3}UN(A|B).*', re.MULTILINE|re.DOTALL)
else:
    EDIDET = re.compile(b'^.{0,3}ISA.*', re.MULTILINE|re.DOTALL)
    EDIFACTDET = re.compile(b'^.{0,3}UN(A|B).*', re.MULTILINE|re.DOTALL)
DFLTSEARCH = (
    SMB2_FILE_ATTRIBUTE_READONLY |
    SMB2_FILE_ATTRIBUTE_HIDDEN |
    SMB2_FILE_ATTRIBUTE_SYSTEM |
    SMB2_FILE_ATTRIBUTE_DIRECTORY |
    SMB2_FILE_ATTRIBUTE_ARCHIVE |
    SMB2_FILE_ATTRIBUTE_NORMAL
)

def set_smb_username(username):
    """
    Set the default username used by SMBPath objects
    """
    global SMB_USER
    SMB_USER = username

def set_smb_password(password):
    """
    Set the default password used by SMBPath objects
    """
    global SMB_PASS
    SMB_PASS = password

class TraxCommonException(Exception):
    """
    Base class for traxcommon exceptions
    """

class FindDfsShare(Exception):
    "Raised when dfs share is not mapped"


def normalize_path(path):
    "Convert an nt style path to posix style"
    return path.replace('\\', '/')


def denormalize_path(path):
    "Convert a posix style path to nt style"
    return path.replace('/', '\\')


def path_is_smb(path):
    "True when a path points to an smb share"
    # XXX This works but is a fairly sketchy check
    if not path_is_posix_style(path):
        path = normalize_path(path)
    return path.startswith('//')


def path_is_posix_style(path):
    """
    Attempt to determine if the path is posix or nt style. If we ar
    unable to determine the path style assume the default for
    whatever system the method is run on
    """
    if path.startswith('/') or (path.count('/') > path.count('\\')):
        return True
    if path.startswith('\\') or (path.count('\\') > path.count('/')):
        return False
    return os.name == 'posix'


class PathFactory(object):
    def __call__(self, path, mode='rb'):
        "Path factory"
        if path_is_smb(path):
            return SMBPath(path, mode)
        return LocalPath(path, mode)


def lower(s):
    return s.lower()


def normalize_domain(path):
    if path.startswith('\\\\'):
        parts = path.split('\\')
        parts[2] = parts[2].lower()
        path = '\\'.join(parts)
    return path


class BasePath(BasicIO):
    """
    Base class for path types to inherit from
    """
    _path_delim = '/'
    _normalize_path = staticmethod(normalize_domain)

    def _set_path(self, path):
        self._original_path = path
        if not self._is_posix_style():
            self.path = self._normalize_path(path)
        else:
            self.path = path

    def _is_posix_style(self, path=None):
        path = path or self._original_path
        return path_is_posix_style(path)

    @property
    def orig_path(self):
        return self._original_path

    def chunked_copy(self, fp, size=1024):
        try:
            while True:
                chunk = fp.read(size)
                if chunk:
                    self.write(chunk)
                    if len(chunk) < size:
                        break
                else:
                    break
        finally:
            pass

    def __str__(self):
        return self.path.encode('utf-8')


class LocalPath(BasePath):

    def __init__(self, path, mode='rb'):
        self._set_path(path)
        self.mode = mode

    @property
    def uri(self):
        return 'file://{}'.format(path)

    @property
    def fp(self):
        if not hasattr(self, '_fp') or not self._fp or self._fp.closed:
            dirname = os.path.dirname(self.path)
            self._fp = io.open(self.path, self.mode)
        return self._fp

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
        dirname = os.path.dirname(self.path)
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
            yield LocalPath(a)

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
            yield LocalPath(a)

    def dirnames(self, glob='*', limit=0):
        for a in self.ls_names(glob, limit=limit):
            if os.path.isdir(a):
                yield a

    def dirs(self, glob='*', limit=0):
        for a in self.dirnames(glob, limit=limit):
            yield LocalPath(a)

    def close(self):
        self.fp.close()

    def remove(self):
        if os.path.isdir(self.path):
            os.rmdir(self.path)
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

def getBIOSName(remote_smb_ip, timeout=30):
    """
    Lookup the NetBIOS name for the given ip
    """
    try:
        bios = nmb.NetBIOS.NetBIOS()
        srv_name = bios.queryIPForName(remote_smb_ip, timeout=timeout)
    finally:
        bios.close()
    if srv_name:
        return srv_name[0]


class NetBiosCache(object):

    def __init__(self, cache=None, expirations=None, ttl=3600):
        if cache is None:
            cache = {}
        if expirations is None:
            expirations = {}
        self.ttl = ttl
        self.cache = cache
        self.expirations = expirations

    def __call__(self, remote_ip, timeout=5):
        if remote_ip not in self.cache or self._is_expired(remote_ip):
            server_bios_name = getBIOSName(remote_ip, timeout=timeout)
            self.cache[remote_ip] = server_bios_name
            self.expirations[remote_ip] = time.time() + self.ttl
        return self.cache[remote_ip]

    def _is_expired(self, name):
        if name not in self.expirations:
            return True
        exp = self.expirations[name]
        if exp <= time.time():
            self.cache.pop(name)
            self.expirations.pop(name)
            return True
        return False


nbcache = NetBiosCache()

class DnsCache(object):

    def __init__(self, cache=None, expirations=None, ttl=1200):
        if cache is None:
            cache = {}
        if expirations is None:
            expirations = {}
        self.ttl = ttl
        self.cache = cache
        self.expirations = expirations

    def __call__(self, name, timeout=15):
        if name not in self.cache or self._is_expired(name):
            ip = socket.gethostbyname(name)
            self.cache[name] = ip
            self.expirations[name] = time.time() + self.ttl
        return self.cache[name]

    def _is_expired(self, name):
        if name not in self.expirations:
            return True
        exp = self.expirations[name]
        if exp <= time.time():
            self.cache.pop(name)
            self.expirations.pop(name)
            return True
        return False

dnscache = DnsCache()

def get_smb_connection(
        server, domain, user, pas, port=139, timeout=30, client=CLIENTNAME,
        is_direct_tcp=False,
    ):
    if is_direct_tcp:
        port = 445
    hostname = "{0}.{1}".format(server, domain)
    try:
        server_ip = dnscache(hostname)
    except socket.gaierror as e:
        log.error(
            "Couldn't resolve hostname: %s",
            hostname
        )
        raise
    server_bios_name = nbcache(server_ip)
    if server_bios_name:
        server_name = server_bios_name
    else:
        server_name = server
    conn = SMBConnection(
        str(user), str(pas), str(client), str(server_name), domain=str(domain), is_direct_tcp=is_direct_tcp
    )
    conn.connect(server_ip, port, timeout=timeout)
    return conn


def smb_dirname(inpath):
    host = None
    if inpath.startswith('\\\\'):
        parts = inpath.strip('\\\\').split('\\', 1)
        if len(parts) == 2:
            host = parts[0]
            path = parts[1]
        else:
            path = inpath[2:]
    else:
        path = inpath
    if inpath.endswith('\\'):
        path = inpath.rstrip('\\')
    if not '\\' in path:
        dirname = '.'
    else:
        dirname = path.rsplit('\\', 1)[0]
    if host:
        return '\\\\' + host + '\\' + (dirname or '\\')
    return dirname or '\\'


def smb_basename(inpath):
    if inpath.startswith('\\\\'):
        path = inpath[2:]
    else:
        path = inpath
    parts = inpath.strip('\\').split('\\')
    return parts[-1] or '\\'


def getFiletime(dt):
    """
    Return a datetime object of the utc time for a smb timestamp
    SMB1: Convert an integer representing the number of 100-nanosecond
    intervals since January 1, 1601 (UTC) to a datetime object.
    SMB2: Convert a float representing the epoc timestamp
    """
    if isinstance(dt, int):
        # Timestamps returned from SMB1
        microseconds = dt / 10.0
        seconds, microseconds = divmod(microseconds, 1000000)
        days, seconds = divmod(seconds, 86400)
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(days, seconds, microseconds)
    else:
        # Timestamps returned from SMB2
        return datetime.datetime.utcfromtimestamp(dt)


class SMBPath(BasePath):
    MAX_CONNECTION_TIME = 60

    def __init__(
            self, path, mode='r', user=None, password=None, api=None,
            clientname=CLIENTNAME, find_dfs_share=find_dfs_share, write_lock=None,
            timeout=120, _attrs=None,
            ):
        #if type(path) == str:
        #    path = path.decode('utf-8')
        self._set_path(path)
        self.find_dfs_share = find_dfs_share
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
        self.ignore_filenames = SMB_IGNORE_FILENAMES
        self._is_direct_tcp = None

    @property
    def uri(self):
        return 'smb://{}.{}/{}/{}'.format(
            self.server_name, self.domain, self.share.replace('\\', '/'),
            self.relpath.replace('\\', '/')
        )

    @classmethod
    def from_uri(cls, uri):
        url.Url(uri)

    def tell(self):
        return self._index

    def seek(self, index, *args):
        self._index = index

    def read(self, size=-1, conn=None):
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
                        timeout=self.timeout, is_direct_tcp = False
                    )
                    self._is_direct_tcp = False
                except error as e:
                    if e.errno != 61 and e.errno != 104 and e.errno != 111:
                        raise
                    self._conn = get_smb_connection(
                        self.server_name, self.domain, self.user, self.password,
                        timeout=self.timeout, is_direct_tcp = True
                    )
                    self._is_direct_tcp = True
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
