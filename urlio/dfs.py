import datetime
import io
import logging
import multiprocessing
import os
import json
import socket
import time
import tempfile
import requests

from smb.SMBConnection import SMBConnection
import repoze.lru

from .base import UrlIOException
from .smb_ext import getDfsReferral

log = logging.getLogger(__name__)

# TODO: Make things more explicity by defining which DC we should talk to, or
# at least have and option to run that way.
DC_BLACKLIST = ['fxdc0013.filex.com', 'fxsjodc0003.filex.com', 'fxdc0015.filex.com']
DFSCACHE = {}
DFSCACHE_PATH = '/tmp/traxcommon.dfscache.json'
AUTO_UPDATE_DFSCACHE = True
DFS_REF_API = "http://dfs-reference-service.s03.filex.com/cache"

def lookupdcs(domain):
    import dns.resolver
    resolver = dns.resolver.Resolver()
    dcs = []
    response = resolver.query('_ldap._tcp.{}'.format(domain), 'srv')
    return response.expiration, [a.target.to_text()[:-1] for a in response]

class _BaseDfsObject(object):

    def _smb_connection(self, server):
        import path
        ip = socket.gethostbyname(server)
        hostname = server.split('.', 1)[0]
        log.debug("_smb_connection: %s %s %s", repr(hostname),
            repr(self.domain), repr(ip)
        )
        con = SMBConnection(path.SMB_USER, path.SMB_PASS, 'client', hostname, self.domain)
        con.connect(ip, timeout=30)
        return con

    def _valid_connection(self, servers):
        valid_servers = [a for a in servers if servers[a]]
        con = None
        for server in valid_servers:
            if server.lower() in DC_BLACKLIST:
                log.debug("Skip blacklisted server: %s", server)
                continue
            try:
                con = self._smb_connection(server)
            except:
                log.exception("Unable to connect: {}".format(server))
                servers[server] = False
                continue
            break
        if not con:
            raise Exception("no valid servers: {}".format(servers))
        return con

class DfsDomain(_BaseDfsObject):

    def __init__(self, domain, dcs=None):
        self.domain = domain
        self._valid_dfs_domain = False
        self._valid_dfs_domain_expires = 0
        if dcs:
            self._dcs = dict.fromkeys(dcs, True)
        else:
            self._dcs = {}
        self._dcs_expire = 0
        self._root_servers = {}
        self._root_servers_expire = 0
        self._namespaces = {}

    def resolve(self, namespace, path):
        if namespace in self._namespaces:
            ns = self._namespaces[namespace]
        else:
            ns = DfsNamespace(self, namespace)
            self._namespaces[ns.name] = ns
        return ns.resolve(path)

    def _get_root_servers(self):
        self._root_servers = {}
        self._root_servers_expire = 0
        con = self._dc_connection()
        data = getDfsReferral(con, 'IPC$', '\\\\{}'.format(self.domain))
        if len(data) > 1:
            raise Exception("Multiple results from root server lookup")
        self._root_servers = dict.fromkeys(
            [str(a[1:]) for a in data[0]['expanded_names']], True
        )
        self._root_servers_expire = time.time() + data[0]['ttl']

    def is_valid(self):
        if not self._valid_dfs_domain_expires or self._valid_dfs_domain_expires < time.time():
            self._validate_dfs_domain()
        return self._valid_dfs_domain

    def _validate_dfs_domain(self):
        self._valid_dfs_domain = False
        self._valid_dfs_domain_expires = 0
        con = self._dc_connection()
        for data in getDfsReferral(con, 'IPC$', ''):
            log.info("Got data from domain request: %s", data)
            if data['special_name'][1:] == self.domain:
                self._valid_dfs_domain = True
                self._valid_dfs_domain_expires = time.time() + data['ttl']


    def _dc_connection(self):
        self._ensure_dcs()
        return self._valid_connection(self._dcs)

    def _root_server_connection(self):
        self._ensure_dcs()
        self._ensure_root_servers()
        return self._valid_connection(self._root_servers)

    def _ensure_root_servers(self):
        if self._root_servers_expired():
            self._get_root_servers()

    def _root_servers_expired(self):
        if not self._root_servers or time.time() > self._root_servers_expire:
            return True
        return False

    def _ensure_dcs(self):
        if self._dcs_expired():
            expires, dcs = self._get_dcs()
            self._dcs_expire = expires
            self._dcs = dict.fromkeys(dcs, True)

    def _dcs_expired(self):
        if not self._dcs or time.time() > self._dcs_expire:
            return True
        return False

    def _get_dcs(self):
        return lookupdcs(self.domain)


class DfsNamespace(_BaseDfsObject):

    def __init__(self, _domain, name):
        self._domain = _domain
        self.name = name
        self._namespace_servers = {}
        self._namespace_servers_expire = 0
        self._paths = {}

    @property
    def domain(self):
        return self._domain.domain

    def _get_namespace_servers(self):
        self._namespace_servers = {}
        self._servers_expirations = {}
        con = self._domain._root_server_connection()
        data = getDfsReferral(con, 'IPC$', '\\\\{}\\{}'.format(self.domain, self.name))
        ttl = 0
        for i in data:
            if not ttl or ttl > i['ttl']:
                ttl = i['ttl']
            hostname = i['network_address_name'].split('\\')[1]
            self._namespace_servers['{}.{}'.format(hostname, self.domain)] = True
        self._namespace_servers_expire = ttl

    def _ensure_namespace_servers(self):
        if self._namespace_servers_expired():
            self._get_namespace_servers()

    def _namespace_servers_expired(self):
        if not self._namespace_servers_expire or time.time() > self._namespace_servers_expire:
            return True
        return False

    def _namespace_server_connection(self):
        self._ensure_namespace_servers()
        return self._valid_connection(self._namespace_servers)

    def resolve(self, path):
        self._purge_expired_paths()
        if path not in self._paths or self._paths[path]['expires'] < time.time():
            con = self._namespace_server_connection()
            unc = '\\\\{}\\{}\\{}'.format(self.domain, self.name, path)
            data = getDfsReferral(con, 'IPC$', unc)
            for i in data:
                log.debug('got share location: %s', i)
            hostname = i['network_address_name'].split('\\')[1].lower()
            self._paths[path] = {
                'expires': time.time() + data[0]['ttl'],
                'server': '{}.{}'.format(hostname, self.domain),
                'share':  '\\'.join(i['network_address_name'].split('\\')[2:]).lower()
            }
            from path import split_host_path
            server, service = split_host_path(i['network_address_name'])
            sharedir = ''
            if '\\' in service:
                service, sharedir = service.split('\\', 1)
            log.info("MEHHH %s %s", data, path)
        return self._paths[path]['server'], self._paths[path]['share']

    def _purge_expired_paths(self):
        for path in self._paths:
            if self._paths[path]['expires'] < time.time():
                self._paths.pop(path)

class DfsResolver(object):

    def __init__(self, resolvers=None):
        self._domains = {}
        if resolvers:
            for resolver in resolvers:
                self._domains[resolver.domain] = resolver

    def resolve_unc(self, unc):
        domain, namespace, path = self.parse_unc_parts(unc)
        if domain in self._domains:
            domain_resolver = self._domains[domain]
        else:
            domain_resolver = DfsDomain(domain)
            self._domains[domain] = domain_resolver
        return domain_resolver.resolve(namespace, path)

    @staticmethod
    def parse_unc_parts(unc):
        if unc.startswith('\\\\'):
            unc = unc[1:]
        unc = unc[1:]
        return unc.split('\\', 2)


class FindDfsShare(Exception):
    "Raised when dfs share is not mapped"


class DfsCache(dict):
    """
    A local copy of the cache file from a dfs reference service instance
        https://github.com/TraxTechnologies/dfs_reference_service
    """
    def __init__(self, cache_file=None):
        super(DfsCache, self).__init__()
        self.fetch_event = multiprocessing.Event()
        self.last_update = datetime.datetime(1970, 1, 1)
        fileno, filename = tempfile.mkstemp(prefix='urlio.dfscache')
        self.filename = filename

    def __del__(self):
        os.remove(self.filename)

    def load(self):
        if not os.path.exists(self.filename) or not self:
            self.fetch()
        if os.path.exists(self.filename):
            with io.open(self.filename, 'r') as f:
                self.update(json.loads(f.read()))
            cache_time = datetime.datetime.utcfromtimestamp(
                int(str(self['timestamp'])[:-3])
            )
            dlt = datetime.datetime.utcnow() - datetime.timedelta(minutes=20)
            if cache_time < dlt:
                log.warn("Dfs cache timestamp is more than 20 minutes old")

    def fetch(self, uri=DFS_REF_API):
        if self.fetch_event.is_set():
            return False
        self.fetch_event.set()
        try:
            response = requests.get(uri, stream=True)
            if response.status_code != 200:
                raise UrlIOException(
                    "Non 200 response: {}".format(response.status_code)
                )
            data = response.json()
            fileno, tmp_filename = tempfile.mkstemp(prefix='urlio.dfscache.download')
            with io.open(tmp_filename, 'wb') as f:
                f.write(
                    json.dumps(
                        data,
                        sort_keys=True,
                        indent=4,
                    ).encode('utf-8')
                )
            try:
                os.chmod(tmp_filename, int('666', 8))
                os.rename(tmp_filename, self.filename)
            except Exception as e:
                log.error("Exception renaming cache %s", str(e)[:75])
            finally:
                os.remove(tmp_filename)
            return self.filename
        except Exception as e:
            log.exception("Exception fetching cache")
            return False
        finally:
            self.last_update = datetime.datetime.utcnow()
            self.fetch_event.clear()


def normalize_domain(path):
    """
    """
    if path.startswith('\\\\'):
        parts = path.split('\\')
        parts[2] = parts[2].lower()
        path = '\\'.join(parts)
    return path


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


def cmp_to_key(mycmp):
    'Convert a cmp= function into a key= function'
    class K:
        def __init__(self, obj, *args):
            self.obj = obj
        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0
        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0
        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0
        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0
        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0
        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0
    return K

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
    sorted_resources = sorted(resources, key=cmp_to_key(by_depth), reverse=True)
    return sorted_resources

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
                if tgt['state'] == 'ONLINE':
                    if test_path.rstrip('\\') == test_uri:
                        return path.rstrip('\\'), tgt
                    return path, tgt

DFSCACHE = DfsCache()
load_dfs_cache = DFSCACHE.load
fetch_dfs_caceh = DFSCACHE.fetch


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
        dfspath = u'\\'.join(parts[4:])
        log.debug("Using parts from uri %s %s %s %s",
            hostname, service, domain, dfspath
        )
        return hostname, service, domain, dfspath.lstrip('\\')
    domain, _ = split_host_path(uri)
    if not DFSCACHE:
        load_dfs_cache()
        log.warn("No dfs cache present")
    elif AUTO_UPDATE_DFSCACHE:
        dlt = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        if DFSCACHE.last_update < dlt:
            if DFSCACHE.fetch():
                load_dfs_cache()
    slashed_domain = u'\\\\{0}'.format(domain).lower()
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
        path = u"{0}\\{1}".format(
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
    server = server
    service = service
    path = path
    domain = domain
    return server, service, domain, path


@repoze.lru.lru_cache(100, timeout=500)
def default_find_dfs_share(uri, **opts):
    return find_dfs_share(uri, **opts)
