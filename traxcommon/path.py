import StringIO
import json
import ConfigParser
import socket
import glob as libglob
import os
import datetime
import requests
import re
import time
import smb
import boto
import hashlib
import magic
import tempfile
from boto.s3.key import Key
import multiprocessing
from smb.SMBConnection import SMBConnection
from smb.SMBConnection import OperationFailure
from smb.smb_constants import *
from smb.smb2_constants import *
import threading
import logging
import repoze.lru
from traxcommon.symbols import ONLINE
from smb_ext import listPath, storeFileFromOffset
log = logging.getLogger(__name__)

CLIENTNAME = 'FileRouter/{}'.format('/'.join(os.uname()))
DFS_REF_API = "http://dfs-reference-service.s03.filex.com/cache"
SMB_USER = os.environ.get('SMBUSER', None)
SMB_PASS = os.environ.get('SMBPASS', None)
DFSCACHE_PATH = '/tmp/traxcommon.dfscache.json'
AUTO_UPDATE_DFSCACHE = True
EDIDET = re.compile('^.{0,3}ISA.*', re.MULTILINE|re.DOTALL)
EDIFACTDET = re.compile('^.{0,3}UN(A|B).*', re.MULTILINE|re.DOTALL)
DFSCACHE = {}
DFLTSEARCH = (
    SMB2_FILE_ATTRIBUTE_READONLY |
    SMB2_FILE_ATTRIBUTE_HIDDEN |
    SMB2_FILE_ATTRIBUTE_SYSTEM |
    SMB2_FILE_ATTRIBUTE_DIRECTORY |
    SMB2_FILE_ATTRIBUTE_ARCHIVE |
    SMB2_FILE_ATTRIBUTE_NORMAL
)

class DfsCache(dict):
    def __init__(self, *args, **opts):
        super(DfsCache, self).__init__(*args, **opts)
        self.fetch_event = multiprocessing.Event()

    def load(self, path=DFSCACHE_PATH):
        if not os.path.exists(path):
            self.fetch(path)
        if os.path.exists(path):
            with open(path, 'r') as f:
                self.update(json.loads(f.read()))

    def fetch(self, path=DFSCACHE_PATH, uri=DFS_REF_API):
        if self.fetch_event.is_set():
            return False
        self.fetch_event.set()
        try:
            response = requests.get(uri, stream=True)
            if response.status_code != 200:
                raise TraxCommonException(
                    "Non 200 response: {}".format(response.status_code)
                )
            data = response.json()
            with open(path, 'wb') as f:
                f.write(
                    json.dumps(
                        data,
                        sort_keys=True,
                        indent=4,
                        separators=(',', ':')
                    )
                )
            return path
        except Exception as e:
            log.exception("Exception fetching cache")
            return False
        finally:
            self.fetch_event.clear()

class TraxCommonException(Exception):
    """
    Base class for traxcommon exceptions
    """

DFSCACHE = DfsCache()
load_dfs_cache = DFSCACHE.load
fetch_dfs_caceh = DFSCACHE.fetch

class FindDfsShare(Exception):
    "Raised when dfs share is not mapped"


def depth_first_resources(domain_cache):
    resources = []
    for ns in domain_cache.copy():
        for resource in domain_cache[ns]:
            path = "{0}\\{1}".format(
                ns.rstrip('\\'), resource.lstrip('\\')
            ).rstrip('\\')
            resources.append(
                (
                    path,
                    domain_cache[ns][resource]
                )
            )
    resources.sort(by_depth, reverse=True)
    return resources


def find_target_in_cache(uri, cache, case_sensative=False):
    if not case_sensative:
        test_uri = uri.lower()
    else:
        test_uri = uri
    if not 'depth_first_resources' in cache:
        cache['depth_first_resources'] = depth_first_resources(cache)
    for path, conf in cache['depth_first_resources']:
        if not case_sensative:
            test_path = path.lower().rstrip('\\')
        else:
            test_path = path.rstrip('\\')
        if test_uri.startswith(test_path + '\\') or test_path == test_uri:
            for tgt in conf['targets']:
                if tgt['state'] == ONLINE:
                    if test_path.rstrip('\\') == test_uri:
                        return path.rstrip('\\'), tgt
                    return path, tgt


def split_host_path(s):
    """
    Given a uri split a hostname/domain from path.

    \\\\filex.com\\foo => filex.com, foo
    \\\\fxaws0108\\foo => fxaws0108, foo
    """
    return s.lstrip('\\').split('\\', 1)


def by_depth(x, y):
    nx = len(x[0].split('\\'))
    ny = len(y[0].split('\\'))
    if nx < ny:
        return -1
    elif nx == ny:
        return 0
    else:
        return 1

def find_dfs_share(uri, **opts):
    case_sensative = opts.get('case_sensative', False)
    log.debug("find dfs share: %s", uri)
    uri = normalize_domain(uri)
    if case_sensative:
        test_uri = uri
    else:
        test_uri = uri.lower()
    parts = uri.split('\\')
    if len(parts[2].split('.')) > 2:
        hostname = parts[2].split('.', 1)[0]
        domain = parts[2].split('.', 1)[1]
        service = parts[3]
        dfspath = '\\'.join(parts[4:])
        log.debug("Using parts from uri %s %s %s %s",
            hostname, service, domain, dfspath
        )
        return hostname, service, domain, dfspath.lstrip('\\')
    domain, _ = split_host_path(uri)
    if not DFSCACHE:
        load_dfs_cache()
        log.warn("No dfs cache present")
    elif AUTO_UPDATE_DFSCACHE:
        cache_time = datetime.datetime.utcfromtimestamp(
            int(str(DFSCACHE['timestamp'])[:-3])
        )
        dlt = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        if cache_time < dlt:
            if DFSCACHE.fetch():
                load_dfs_cache()
    slashed_domain = '\\\\{0}'.format(domain).lower()
    if slashed_domain in DFSCACHE:
        domain_cache = DFSCACHE[slashed_domain]
    else:
        errmsg = "Domain not in cache: {}".format(domain)
        raise FindDfsShare(errmsg)
    result = find_target_in_cache(test_uri, domain_cache, case_sensative)
    if not result:
        raise FindDfsShare("No dfs cache result found")
    path, tgt = result
    server, service = split_host_path(tgt['target'])
    sharedir = ''
    if '\\' in service:
        service, sharedir = service.split('\\', 1)
    if domain.count('.') > 1:
        domain = '.'.join(domain.split('.')[-2:])
    part = uri.lower().split(path.lower(), 1)[1]
    if len(part):
        path = "{0}\\{1}".format(
            sharedir, uri[-len(part):].lstrip('\\')
        ).strip('\\')
    else:
        path = sharedir
    data = {
        'host': server,
        'service': service,
        'domain': domain,
        'path': path,
    }
    server = server.encode('cp1251')
    service = service.encode('cp1251')
    path = path.encode('cp1251')
    domain = domain.encode('cp1251')
    return server, service, domain, path


@repoze.lru.lru_cache(100, timeout=500)
def default_find_dfs_share(uri, **opts):
    return find_dfs_share(uri, **opts)


def normalize_path(path):
    "Convert an nt style path to posix style"
    return path.replace('\\', '/')


class WriteLock(object):

    def __init__(self, locks=None):
        if not locks:
            locks = {}
        self.locks = {}

    def acquire(self, server, share, path):
        key = (server, share, path)
        log.debug('write-lock acquire: %s', key)
        if key not in self.locks:
            self.locks[key] = multiprocessing.Lock()
        self.locks[key].acquire()

    def release(self, server, share, path):
        key = (server, share, path)
        log.debug('write-lock release: %s', key)
        if key not in self.locks:
            log.debug('write-lock release but adding lock: %s', key)
            self.locks[key] = multiprocessing.Lock()
        log.debug('write-lock release call: %s', key)
        self.locks[key].release()
        self.locks.pop(key)


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


def Path(path, mode='r'):
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

class BasePath(object):
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
        return self.path


class LocalPath(BasePath):

    def __init__(self, path, mode='r'):
        self._set_path(path)
        self.mode = mode

    @property
    def fp(self):
        if not hasattr(self, '_fp') or not self._fp or self._fp.closed:
            dirname = os.path.dirname(self.path)
            self._fp = open(self.path, self.mode)
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

    @staticmethod
    def join(dirname, basename):
        return "{0}/{1}".format(dirname, basename)

    def readline(self):
        return self.fp.readline()

    def readlines(self):
        return self.fp.readlines()

    @property
    def size(self):
        return os.stat(self.path).st_size

    @property
    def mtime(self):
        return datetime.datetime.utcfromtimestamp(os.stat(self.path).st_mtime)

    @property
    def atime(self):
        return datetime.datetime.utcfromtimestamp(os.stat(self.path).st_atime)

    def makedirs(self, is_dir=False):
        if is_dir:
            os.makedirs(self.path)
        else:
            os.makedirs(self.basename)

    def stat(self):
        return {
            'size': self.size,
            'atime': self.atime,
            'mtime': self.mtime,
        }



def get_smb_connection(
        server, domain, user, pas, port=139, timeout=30, client=CLIENTNAME,
        is_direct_tcp=True,
    ):
    if is_direct_tcp:
        port = 445
    hostname = "{0}.{1}".format(server, domain)
    try:
        server_ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        log.error(
            "Couldn't resolve hostname: %s",
            hostname
        )
        raise
    conn = SMBConnection(
        user, pas, client, server, domain=domain, is_direct_tcp=is_direct_tcp
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

    def __init__(
            self, path, mode='r', user=None, password=None, api=None,
            clientname=CLIENTNAME, find_dfs_share=None, write_lock=None,
            timeout=120, _attrs=None,
            ):
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
        return 'smb://{}.{}/{}/{}'.format(
            self.server_name, self.domain, self.share.replace('\\', '/'),
            self.relpath.replace('\\', '/')
        )

    def tell(self):
        return self._index

    def seek(self, index, *args):
        self._index = index

    def read(self, size=-1, conn=None):
        if conn is None:
            conn = self.get_connection()
        fp = StringIO.StringIO()
        conn.retrieveFileFromOffset(
            self.share, self.relpath, fp, self._index, size
        )
        self._index = self._index + fp.tell()
        fp.seek(0)
        return fp.read()

    def get_connection(self):
        if not self._conn:
            self._conn = get_smb_connection(
                self.server_name, self.domain, self.user, self.password,
                timeout=self.timeout
            )
        return self._conn

    def exists(self, relpath=None):
        conn = self.get_connection()
        try:
            stat = conn.getAttributes(self.share, self.relpath)
        except OperationFailure:
            return False
        return stat != None

    def makedirs(self, relpath=None, is_dir=False):
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
                path = '{0}\\{1}'.format(path, a)
                try:
                    c.listPath(self.share, path, timeout=self.timeout)
                except smb.smb_structs.OperationFailure as e:
                    pass
                else:
                    continue
                try:
                    c.createDirectory(self.share, path)
                except smb.smb_structs.OperationFailure as e:
                    pass
                exists = True
                try:
                    c.listPath(self.share, path, timeout=self.timeout)
                except smb.smb_structs.OperationFailure:
                    exists = False
                if not exists:
                    raise e
        finally:
            if self.WRITELOCK:
                self.WRITELOCK.release(self.server_name, self.share, self.relpath)

    def write(self, fp):
        if not hasattr(fp, 'read'):
            fp = StringIO.StringIO(fp)
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

    def files(self, glob='*', limit=0, recurse=False):
        return self.ls(
            glob=glob, smb_attribs=SMB2_FILE_ATTRIBUTE_NORMAL, limit=limit,
            recurse=recurse
        )

    def filenames(self, glob='*', limit=0, recurse=False):
        return self.ls_names(
            glob=glob, smb_attribs=SMB2_FILE_ATTRIBUTE_NORMAL, limit=limit,
            recurse=recurse
        )

    def dirs(self, glob='*', limit=0, recurse=False):
        return self.ls(
            glob=glob,
            limit=limit,
            recurse=recurse,
            return_files=False
        )

    def dirnames(self, glob='*', limit=0):
        return self.ls_names(
            glob=glob,
            limit=limit,
            recurse=recurse,
            return_files=False
        )

    def close(self):
        self.get_connection().close()

    def ls(
            self, glob='*', smb_attribs=DFLTSEARCH, limit=0, recurse=False,
            return_files=True, _done=0
        ):
        """
        List a directory and return the names of the files and directories.
        """
        conn = self.get_connection()
        paths = []
        request_dirs = smb_attribs & SMB2_FILE_ATTRIBUTE_DIRECTORY == SMB2_FILE_ATTRIBUTE_DIRECTORY
        if recurse and not request_dirs:
            useattribs = smb_attribs | SMB2_FILE_ATTRIBUTE_DIRECTORY
        else:
            useattribs = smb_attribs
        print 'request_dirs', request_dirs, useattribs
        try:
            paths = listPath(
                conn,
                self.share,
                self.relpath,
                search=useattribs,
                pattern=glob,
                limit=limit,
                timeout=self.timeout,
            )
        except smb.smb_structs.OperationFailure as e:
            # Determine if this failure is due to an invalid path or just
            # because the glob didn't return any results.
            # TODO: This seesms strange and possible buggy
            if glob != '*':
                self.ls('*')
            else:
                log.error("Directory does not exist: %s", self.orig_path)
        finally:
            pass
        for a in paths:
            if limit > 0 and _done >= limit:
                raise StopIteration
            if a.filename in ['.', '..']:
                continue
            if a.isDirectory:
                p = self.join(a.filename.encode('iso-8859-1'), _attrs=a)
                if request_dirs:
                    yield p
                    _done += 1
                if recurse:
                    for _ in p.ls(
                            glob, smb_attribs, limit, recurse, return_files, _done
                        ):
                        yield _
                        _done += 1
            elif return_files:
                yield Path(self.path).join(
                    a.filename.encode('iso-8859-1'), _attrs=a
                )
                _done += 1

    def recurse_files(self, glob='*', limit=0):
        return self.filenames(glob=glob, recurse=True, limit=limit)

    def recurse(self, glob='*', smb_attribs=DFLTSEARCH, limit=0):
        return self.ls_names(
            glob, smb_attribs, limit, recurse=True, return_dirs=True
        )

    def ls_names(
            self, glob='*', smb_attribs=DFLTSEARCH, limit=0, recurse=False,
            return_dirs=True, _done=0
        ):
        """
        List a directory and return the names of the files and directories.
        """
        for a in self.ls(glob, smb_attribs, limit, recurse, return_dirs):
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
    def atime(self):
        if not self._attrs:
            conn = self.get_connection()
            self._attrs = conn.getAttributes(self.share, self.relpath)
        return getFiletime(self._attrs.last_access_time)

    @property
    def mtime(self):
        if not self._attrs:
            conn = self.get_connection()
            self._attrs = conn.getAttributes(self.share, self.relpath)
        return getFiletime(self._attrs.last_write_time)

    @property
    def size(self):
        if not self._attrs:
            conn = self.get_connection()
            self._attrs = conn.getAttributes(self.share, self.relpath)
        return self._attrs.file_size

    def stat(self):
        if not self._attrs:
            conn = self.get_connection()
            self._attrs = conn.getAttributes(self.share, self.relpath)
        return {
           'size': self._attrs.file_size,
           'atime': getFiletime(self._attrs.last_access_time),
           'mtime': getFiletime(self._attrs.last_write_time)
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

    def join(self, joinpath, **kwargs):
        return SMBPath(self.static_join(self.path, joinpath), **kwargs)

    @staticmethod
    def static_join(dirname, basename):
        return "{0}\\{1}".format(
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
        conn = self.get_connection()
        stat = conn.getAttributes(self.share, self.relpath)
        return stat.isDirectory


def mimeencoding_from_buffer(buffer):
    m = magic.open(magic.MAGIC_MIME_ENCODING)
    if m.load() != 0:
        m.close()
        raise Exception("Unable to load magic database")
    rslt = m.buffer(buffer)
    m.close()
    return rslt


def mimeencoding(path):
    m = magic.open(magic.MAGIC_MIME_ENCODING)
    if m.load() != 0:
        m.close()
        raise Exception("Unable to load magic database")
    rslt = m.file(path)
    m.close()
    return rslt

def mimetype_from_buffer(buffer):
    m = magic.open(magic.MAGIC_MIME_TYPE)
    if m.load() != 0:
        m.close()
        raise Exception("Unable to load magic database")
    s = m.buffer(buffer)
    m.close()
    if EDIDET.search(buffer):
        s = "application/EDI-X12"
    elif EDIFACTDET.search(buffer):
        s = "application/EDIFACT"
    return s

def mimetype(path):
    m = magic.open(magic.MAGIC_MIME_TYPE)
    if m.load() != 0:
        m.close()
        raise Exception("Unable to load magic database")
    s = m.file(path)
    m.close()
    if EDIDET.search(buffer):
        s = "application/EDI-X12"
    elif EDIFACTDET.search(buffer):
        s = "application/EDIFACT"
    return s
