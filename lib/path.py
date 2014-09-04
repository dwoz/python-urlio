import StringIO
import json
import ConfigParser
import socket
import glob
import os
import requests
import smb
import multiprocessing
from threading import Lock
from smb.SMBConnection import SMBConnection
import logging
import repoze.lru
from traxcommon.symbols import ONLINE
log = logging.getLogger(__name__)

CLIENTNAME = 'FileRouter'
DFS_REF_API = "http://dfs-reference-dev.s03.filex.com/cache/"
SMB_USER = os.environ.get('SMBUSER', None)
SMB_PASS = os.environ.get('SMBPASS', None)

DFSCACHE = {}

def load_cache(path='/tmp/dfscache', fetch=True):
    if not os.path.exists(path):
        if fetch:
            fetch_dfs_cache(path)
    if os.path.exists(path):
        with open(path, 'r') as f:
            DFSCACHE.update(json.loads(f.read()))


class FindDfsShare(Exception):
    "Raised when dfs share is not mapped"


def fetch_dfs_cache(path, uri=None):
    uri = uri or DFS_REF_API
    r = requests.get(uri, stream=True)
    with open(path, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk: # filter out keep-alive new chunks
                f.write(chunk)
                f.flush()
    return path


def split_host_path(s):
    """
    Given a uri split a hostname/domain from path.

    \\\\filex.com\\foo => filex.com, foo
    \\\\fxaws0108\\foo => fxaws0108, foo
    """
    return s.lstrip('\\').split('\\', 1)


def find_target_in_cache(uri, cache):
    for path, conf in depth_first_resources(cache):
        if uri.lower().startswith(path.lower() + '\\'):
            for tgt in conf['targets']:
                if tgt['state'] == ONLINE:
                    return path, tgt


def by_depth(x, y):
    nx = len(x[0].split('\\'))
    ny = len(y[0].split('\\'))
    if nx < ny:
        return -1
    elif nx == ny:
        return 0
    else:
        return 1


def depth_first_resources(domain_cache):
    resources = []
    for ns in domain_cache:
        for resource in domain_cache[ns]:
            resources.append(
                (
                    "{0}\\{1}".format(ns, resource),
                    domain_cache[ns][resource]
                )
            )
    resources.sort(by_depth, reverse=True)
    return resources


@repoze.lru.lru_cache(500)
def default_find_dfs_share(uri, **opts):
    uri = uri.lower()
    parts = uri.split('\\')
    if len(parts[2].split('.')) > 2:
        hostname = parts[2].split('.', 1)[0]
        domain = parts[2].split('.', 1)[1]
        service = parts[3]
        dfspath = '\\'.join(parts[4:])
        log.debug("Using parts from uri %s %s %s %s",
            hostname, service, domain, dfspath
        )
        return hostname, service, domain, '\\' + dfspath
    domain, _ = split_host_path(uri)
    domain_cache = DFSCACHE['\\\\{0}'.format(domain)]
    assert domain_cache
    result = find_target_in_cache(uri, domain_cache)
    if not result:
        log.error("No domain cache found")
    path, tgt = result
    server, service = split_host_path(tgt['target'])
    sharedir = ''
    if '\\' in service:
        service, sharedir = service.split('\\', 1)
    if domain.count('.') > 1:
        domain = '.'.join(domain.split('.')[-2:])
    path = "{0}\\{1}".format(
        sharedir, uri.lower().split(path.lower(), 1)[1]
    ).lstrip('\\')
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
            self.locks[key] = multiprocessing.Lock()
        self.locks[key].release()


WRITELOCK = WriteLock()


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

class BasePath(object):
    """
    Base class for path types to inherit from
    """
    _path_delim = '/'
    _normalize_path = staticmethod(lower)

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

    def seek(self, index):
        self.fp.seek(index)

    def tell(self):
        return self.fp.tell()

    def read(self, size=-1):
        return self.fp.read(size)

    def write(self, s):
        dirname = os.path.dirname(self.path)
        if dirname and not os.path.exists(dirname):
            os.makedirs(dirname)
        self.fp.write(s)

    def exists(self):
        return os.path.exists(self.path)

    def ls(self, glb):
        for a in glob.glob(os.path.join(self.path, glb)):
            yield a

    def files(self, glob='*'):
        for a in self.ls(glob):
            if os.path.isfile(a):
                yield a

    def close(self):
        self.fp.close()

    def remove(self):
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


def get_smb_connection(
        server, domain, user, pas, port=139, timeout=30, client=CLIENTNAME,
    ):
    hostname = "{0}.{1}".format(server, domain)
    try:
        server_ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        log.error(
            "Couldn't resolve hostname: %s",
            hostname
        )
        raise
    conn = SMBConnection(user, pas, client, server, domain=domain)
    conn.connect(server_ip, 139, timeout=30)
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


class SMBPath(BasePath):

    WRITELOCK = WRITELOCK

    def __init__(
            self, path, mode='r', user=None, password=None, api=None,
            clientname=CLIENTNAME, find_dfs_share=None, write_lock=None
            ):
        self._set_path(path)
        find_dfs_share = find_dfs_share or default_find_dfs_share
        server_name, share, domain, relpath = find_dfs_share(self.path)
        self.server_name = server_name
        self.share = share
        self.relpath = relpath
        self.domain = domain
        self.user = user or SMB_USER
        self.password = password or SMB_PASS
        self.clientname = clientname
        self._index = 0
        self.mode = mode
        self._conn = None
        if write_lock:
            self.WRITELOCK = write_lock

    def tell(self):
        return self._index

    def seek(self, index):
        self._index = index

    def read(self, size=-1, con=None):
        fp = StringIO.StringIO()
        conn = self.get_connection()
        conn.retrieveFileFromOffset(
            self.share, self.relpath, fp, self._index, size
        )
        self._index = self._index + fp.tell()
        fp.seek(0)
        return fp.read()

    def get_connection(self):
        if not self._conn:
            self._conn = get_smb_connection(
                self.server_name, self.domain, self.user, self.password
            )
        return self._conn

    def exists(self, relpath=None):
        relpath = relpath or self.relpath
        conn = self.get_connection()
        rel_dirname = smb_dirname(relpath).lower()
        rel_basename = smb_basename(relpath).lower()
        self.WRITELOCK.acquire(self.server_name, self.share, relpath)
        try:
            paths = conn.listPath(
                self.share, rel_dirname,
            )
            exists = rel_basename in [i.filename.lower() for i in paths]
            log.debug(
                "exists: %s, %s %s",
                rel_basename,
                [i.filename for i in paths],
                exists
            )
        except smb.smb_structs.OperationFailure as e:
            exists = False
        finally:
            self.WRITELOCK.release(self.server_name, self.share, relpath)
        return exists

    def makedirs(self, relpath=None, is_dir=False):
        if not relpath:
            relpath = self.relpath
        c = self.get_connection()
        if is_dir:
            dirs = relpath.split('\\')
        else:
            dirs = relpath.split('\\')[:-1]
        path = ''
        self.WRITELOCK.acquire(self.server_name, self.share, self.relpath)
        try:
            for a in dirs:
                path = '{0}\\{1}'.format(path, a)
                try:
                    c.listPath(self.share, path)
                except smb.smb_structs.OperationFailure as e:
                    pass
                else:
                    continue
                log.info("Create dir %s", path)
                try:
                    c.createDirectory(self.share, path)
                except smb.smb_structs.OperationFailure as e:
                    pass
                exists = True
                try:
                    c.listPath(self.share, path)
                except smb.smb_structs.OperationFailure:
                    exists = False
                if not exists:
                    raise e
        finally:
            self.WRITELOCK.release(self.server_name, self.share, self.relpath)

    def write(self, fp):
        if not hasattr(fp, 'read'):
            fp = StringIO.StringIO(fp)
        if self.mode == 'r':
            raise Exception("File not open for writing")
        if not SMBPath(self.dirname).exists():
            log.info("Make base dir: %s", self.rel_dirname)
            self.makedirs()
        else:
            log.debug("Base dir exists: %s", self.rel_dirname)
        self.WRITELOCK.acquire(self.server_name, self.share, self.relpath)
        try:
            conn = self.get_connection()
            conn.storeFile(self.share, self.relpath, fp)
        finally:
            self.WRITELOCK.release(self.server_name, self.share, self.relpath)

    def files(self, glob='*'):
        for a in self.ls(glob):
            if not a.isDirectory:
                yield "{0}\\{1}".format(self.orig_path, a.filename)

    def close(self):
        pass

    def ls(self, glob='*'):
        conn = self.get_connection()
        paths = []
        try:
            paths = conn.listPath(self.share, self.relpath, pattern=glob)
        except smb.smb_structs.OperationFailure as e:
            # Determine if this failure is due to an invalid path or just
            # because the glob didn't return any results.
            if glob != '*':
                self.ls('*')
            else:
                log.error("Directory does not exist: %s", self.orig_path)
        finally:
            pass
        return paths

    def remove(self):
        conn = self.get_connection()
        self.WRITELOCK.acquire(self.server_name, self.share, self.relpath)
        try:
            conn.deleteFiles(self.share, self.relpath)
        finally:
            self.WRITELOCK.release(self.server_name,  self.share, self.relpath)

    @staticmethod
    def _dirname(inpath):
        return smb_dirname(inpath)
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
        dirname = path.rsplit('\\', 1)[0]
        if host:
            return '\\\\' + host + '\\' + (dirname or '\\')
        return dirname or '\\'

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

    @staticmethod
    def join(dirname, basename):
        return "{0}\\{1}".format(dirname, basename)

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
