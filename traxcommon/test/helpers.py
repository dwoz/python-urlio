import os
from six.moves.urllib.parse import urlparse, parse_qs
import six


PY3 = six.PY3

def data_path(filename):
    return os.path.join(os.path.dirname(__file__), 'data', filename)

class ParsedUrl(object):
    """
    Simple parsed url object to help test for url equality
    """

    def __init__(self, url):
        self._url = url
        self._urlparse = urlparse(self._url)
        self._params = parse_qs(self._urlparse.query)

    @property
    def scheme(self):
        return self._urlparse.scheme

    @property
    def netloc(self):
        return self._urlparse.netloc

    @property
    def path(self):
        return self._urlparse.path

    @property
    def fragment(self):
        return self._urlparse.fragment

    @property
    def params(self):
        return self._params

    def __repr__(self):
        return '<ParsedUrl({} {} {} {} {}) at {}>'.format(
            self.scheme, self.netloc, self.path, self.fragment, self.params,
            hex(id(self))
        )

    def __eq__(self, other):
        return (
            self.scheme == other.scheme and
            self.netloc == other.netloc and
            self.path == other.path and
            self.fragment == other.fragment and
            self.params == other.params
        )
