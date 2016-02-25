import socket
from smb.SMBConnection import SMBConnection
import dns.resolver
import path
import logging
import time
from smb_ext import getDfsReferral

log = logging.getLogger(__name__)


def lookupdcs(domain):
    resolver = dns.resolver.Resolver()
    dcs = []
    response = resolver.query('_ldap._tcp.{}'.format(domain), 'srv')
    return response.expiration, [a.target.to_text()[:-1] for a in response]

class _BaseDfsObject(object):

    def _smb_connection(self, server):
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
            try:
                con = self._smb_connection(server)
            except:
                log.exception("Unable to connect: {}".format(server))
                servers[dc] = False
                continue
            break
        if not con:
            raise Exception("no valid servers: {}".format(servers))
        return con

class DfsDomain(_BaseDfsObject):

    def __init__(self, domain):
        self.domain = domain
        self._valid_dfs_domain = False
        self._valid_dfs_domain_expires = 0
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
        data = con.getDfsReferral('IPC$', '\\\\{}'.format(self.domain))
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
        for data in con.getDfsReferral('IPC$', ''):
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
        data = con.getDfsReferral('IPC$', '\\\\{}\\{}'.format(self.domain, self.name))
        ttl = 0
        for i in data:
            if not ttl or ttl > i['ttl']:
                ttl = i['ttl']
            hostname = i['network_address_name'].split('\\')[1]
            self._namespace_servers['{}.{}'.format(hostname, domain)] = True
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
            data = con.getDfsReferral('IPC$', unc)
            for i in data:
                log.debug('got share location: %s', i)
            hostname = i['network_address_name'].split('\\')[1].lower()
            self._paths[path] = {
                'expires': time.time() + data[0]['ttl'],
                'server': '{}.{}'.format(hostname, self.domain),
                'share':  '\\'.join(i['network_address_name'].split('\\')[2:]).lower()
            }
        return self._paths[path]['server'], self._paths[path]['share']

    def _purge_expired_paths(self):
        for path in self._paths:
            if self._paths[path]['expires'] < time.time():
                self._paths.pop(path)

class DfsResolver(object):

    def __init__(self):
        self._domains = {}

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
