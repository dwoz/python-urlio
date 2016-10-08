"""
Create and parse uriversal resource identifiers
"""
from six.moves.urllib.parse import urlparse, parse_qs, urlencode
import re

class STRINGRE:
    quad      = '(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    ipv4      = '^(?:%s\.){3}%s$' % (quad, quad)
    ipv6      = '^((([0-9A-Fa-f]{1,4}:){7}(([0-9A-Fa-f]{1,4})|:))|(([0-9A-Fa-f]{1,4}:){6}(:|((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})|(:[0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:)(:[0-9A-Fa-f]{1,4}){0,4}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(:(:[0-9A-Fa-f]{1,4}){0,5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})))(%.+)?$'


class RE:
    ipv4       = re.compile(STRINGRE.ipv4)
    ipv6       = re.compile(STRINGRE.ipv6)


def is_ipv4(s):
    """
    Return True if given string is an IPv4 address.
    """
    return bool(RE.ipv4.search(s))


def is_ipv6(s):
    """
    Return True if given string is an IPv6 address.
    """
    return not is_ipv4(s) and bool(RE.ipv6.search(s))

class DataDict(dict):
    def __init__(self, *args, **kwargs):
        super(DataDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


class Uri(object):
    """
    Parse a string uri and provied access to the parsed host, port, proto,
    username, password, path, fragment, and inputs.
    """

    @property
    def protocol(self):
        if not self.parsed.scheme:
            return ''
        return self.parsed.scheme
    @protocol.setter
    def protocol(self, protocol):
        self.__init__(self.str(self.dict(), protocol=protocol))

    @property
    def has_protocol(self):
        return True if self.parsed.scheme else False

    @property
    def username(self):
        credentials, host, port = self.parse_netloc()
        if credentials:
            return credentials.split(':')[0]
    @username.setter
    def username(self, username):
        self.__init__(self.str(self.dict(), username=username))

    @property
    def password(self):
        credentials, host, port = self.parse_netloc()
        if credentials and ':' in credentials:
            return credentials.split(':')[1]
    @password.setter
    def password(self, password):
        self.__init__(self.str(self.dict(), password=password))

    @property
    def host(self):
        credentials, host, port = self.parse_netloc()
        return host
    @host.setter
    def host(self, host):
        self.__init__(self.str(self.dict(), host=host))

    @property
    def port(self):
        credentials, host, port = self.parse_netloc()
        if not port and self.protocol == 'http':
            return 80
        elif not port and self.protocol == 'https':
            return 443
        return port
    @port.setter
    def port(self, port):
        self.__init__(self.str(self.dict(), port=port))

    @property
    def path(self):
        return self.parsed.path or ''
    @path.setter
    def path(self, path):
        self.__init__(self.str(self.dict(), path=path))

    @property
    def inputs(self):
        """
        The query string part of the uri as a dict returned by urlparse.parse_qs.
        """
        return parse_qs(self.parsed.query, True)
    @inputs.setter
    def inputs(self, inputs):
        self.__init__(self.str(self.dict(), inputs=inputs))

    @property
    def fragment(self):
        return self.parsed.fragment
    @fragment.setter
    def fragment(self, fragment):
        self.__init__(self.str(self.dict(), fragment=fragment))

    @property
    def site(self):
        return self.sitestr(self.dict())
    @site.setter
    def site(self, s):
        site = Uri(s)
        self.__init__(self.str(self.dict(), protocol=site.protocol, username=site.username,
            password=site.password, host=site.host, port=site.port))

    def __init__(self, uri=''):
        if isinstance(uri, Uri):
            self.parsed = uri.parsed
        else:
            self.parsed = urlparse(uri)

    def __repr__(self):
        return 'Uri : {0}'.format(str(self))

    def __str__(self):
        return self.str(self.dict())

    def __hash__(self):
        return hash(str(self))

    def __cmp__(self, other):
        if isinstance(other, Uri):
            other = str(other)
        else:
            other = str(Uri(other))
        return cmp(str(self), other)

    def parse_netloc(self, netloc=None):
        """
        Parse credentials, host and port from a netloc string. Netloc is a host
        with optional credentials and port. This is an override to support IPv6
        hosts in URLs which are not supported in the python standard library
        until 3.2.
        """
        if not netloc:
            netloc = self.parsed.netloc
        credentials, host, port = None, None, None
        try:
            credentials, host_part = netloc.split('@')
        except:
            credentials, host_part = None, self.parsed.netloc
        if ']' in host_part:
            host_part, port_part = host_part.split(']')
            host = host_part.strip('[')
            if port_part:
                port = int(port_part.strip(':'))
        else:
            try:
                host, port_part = host_part.split(':')
            except:
                host, port_part = host_part, None
            if port_part:
                port = int(port_part)
        return credentials, host, port

    def haschild(self, uri):
        """
        True when the given Uri instance is child directory of this Uri.

        Examples:

          http://foo.com/ has child http://foo.com/index.html
          http://foo.com/bar/ has child http://foo.com/bar/bang
          http://foo.com/bar.html/ has child http://foo.com/bar.html/bang
          http://foo.com/bar has child http://foo.com/bar

          http://foo.com/ does not have https://foo.com/index.html
          http://foo.com/bar/ does not have http://foo.com:8080/bar/bang
          http://foo.com/index.html does not have child http://foo.com/index/index.html
          http://foo.com/bar does not have child http://foo.com/bar/bang
        """ 
        if self.protocol == uri.protocol and self.username == uri.username and \
            self.password == uri.password and self.host == uri.host and self.port == uri.port:
            # If this uri is the root then the other must be a subdir or
            # if the two paths are the same they are subdirs of eachother.
            if self.path == '/' or self.path == uri.path:
                return True
            if self.path[-1] != '/':
                return False
            path = self.path.split('/')
            other_path = uri.path.split('/')
            if len(other_path) < len(path):
                return False
            # The last item in path is a blank string '', remove it since 
            # other's path won't match this.
            path.pop(-1)
            # For each dir in the path check to make sure the other path
            # has a matching dir.
            for n, i in enumerate(path):
                if other_path[n] != i:
                    return False
            return True
        else:
            return False

    def ischild(self, uri):
        """
        True when this Uri is a child of the given uri instance.
        """
        return uri.haschild(self)

    @classmethod
    def str(C, *l, **opts):
        """
        Return a normalized string from a dictionary of Uri options.
          * protocol => Protocol (defaults to 'file')
          * username = Username (optional)
          * password = Password (optional)
          * hostname = Hostname
          * port = Port eg. 8080 (optional)
          * path = Pathname (optional)
          * inputs = Query as a dictionary object (optional)
          * fragment = Fragment (optional)
        """
        if not l:
           d = {}
        else:
            l = list(l)
            d = l.pop()
            while l:
                d.update(l.pop())
        opts = DataDict(d, **opts)
        # We want the site string but remove the '/' portion.
        s = C.sitestr(opts)[:-1]
        if 'path' in opts:
            if opts.path[0] != '/':
                opts.path = '/{0}'.format(opts.path)
            s = '{0}{1}'.format(s, opts.path)
        if 'inputs' in opts:
            opts.inputs = dict(sorted(opts.inputs.items()))
            s = '{0}?{1}'.format(s, urlencode(opts.inputs, doseq=True))
        if 'fragment' in opts:
            s = '{0}#{1}'.format(s, opts.fragment)
        return s

    @classmethod
    def sitestr(C, *l, **opts):
        """
        Return a normalized site string from a dictionary of Uri options.
        The site is mad up of a protocol (default is file) and includes user
        name, password, host, port if they exist. The root directory is implied.
        Called with no inputs will return: file:///
        """
        if not l:
           d = {}
        else:
            l = list(l)
            d = l.pop()
            while l:
                d.update(l.pop())
        opts = DataDict(d, **opts)
        s = ''
        if 'protocol' in opts:
            s += '{0}://'.format(opts.protocol)
        auth = ''
        if 'username' in opts:
            auth = '{0}'.format(opts.username)
        if 'password' in opts:
            auth = '{0}:{1}'.format(auth, opts.password)
        if auth:
            s = '{0}{1}@'.format(s, auth)
        if 'host' in opts:
            if is_ipv6(opts.host):
                opts.host = '[{0}]'.format(opts.host)
            s = '{0}{1}'.format(s, opts.host)
        if 'port' in opts and 'protocol' in opts and opts['port'] == 80 and opts['protocol'] == 'http':
            s = '{0}/'.format(s)
        elif 'port' in opts and 'protocol' in opts and opts['port'] == 443 and opts['protocol'] == 'https':
            s = '{0}/'.format(s)
        elif 'port' in opts:
            s = '{0}:{1}/'.format(s, opts.port)
        else:
            s = '{0}/'.format(s)
        return s

    def dict(self, *l, **opts):
        d = dict()
        for n in ['protocol', 'username', 'password', 'host', 'port', 'path', 'inputs', 'fragment']:
            v = getattr(self, n, None)
            if v:
                d[n] = v
        for i in l:
            d.update(i)
        d.update(opts)
        return d

    def json(self):
        return str(self)

def relative_uri(uri, referer):
    """
    Create a uri from a relative link and referer.
    """
    uri = Uri(uri)
    base = Uri(referer).site[:-1]
    # If the uri starts with / it is relative to the site's root.
    if uri.path:
        if uri.path[0] == '/':
            uri = Uri('{0}{1}'.format(base, uri.path))
        # If the uri starts with . figure out the actual relative path.
        elif uri.path[0] == '.':
            relpath = uri.path.split('/')
            referpath = Uri(referer).path.split('/')[1:-1]
            for n, i in enumerate(relpath):
                if i != '..' and i != '.':
                    break
                elif i == '.':
                    pass
                elif i == '..':
                    try:
                        referpath.pop(-1)
                    except IndexError:
                        pass
            relpath = relpath[n:]
            if referpath:
                uri = Uri('{0}/{1}/{2}'.format(base, '/'.join(referpath), '/'.join(relpath)))
            else:
                uri = Uri('{0}/{1}'.format(base, '/'.join(relpath)))
        # The uri doesn't start with / or . so its relative to referer
        else:
            if Uri(referer).path:
                saneref = str(Uri(referer))
                referer = '/'.join(saneref.split('/')[:-1])
            uri = Uri('{0}/{1}'.format(referer, uri.path))
    return uri
