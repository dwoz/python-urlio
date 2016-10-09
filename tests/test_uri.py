from urlio.uri import Uri, relative_uri, is_ipv6

import pytest

def test_ipv61():
    'fe80:0000:0000:0000:0204:61ff:fe9d:f156 is full IPv6 address'
    assert is_ipv6('fe80:0000:0000:0000:0204:61ff:fe9d:f156')

def test_ipv62():
    'fe800:0000:0000:0000:0204:61ff:fe9d:f156 is not an IPv6 address'
    assert not is_ipv6('fe800:0000:0000:0000:0204:61ff:fe9d:f156')

def test_ipv63():
    'fe80:0:0:0:204:61ff:fe9d:f156 is partially collapsed IPv6 address'
    assert is_ipv6('fe80:0:0:0:204:61ff:fe9d:f156')

def test_ipv64():
    'fe80::204:61ff:fe9d:f156 is collapsed IPv6 address'
    assert is_ipv6('fe80::204:61ff:fe9d:f156')

def test_ipv65():
    'fe80:0000:0000:0000:0204:61ff:254.157.241.086 is IPv6 dot decimal address'
    return is_ipv6('fe80:0000:0000:0000:0204:61ff:254.157.241.086')

def test_ipv67():
    'fe80:0:0:0:0204:61ff:254.157.241.86 is partially collpased IPv6 dot decimal address'
    assert is_ipv6('fe80:0:0:0:0204:61ff:254.157.241.86')

def test_ipv68():
    'fe80::204:61ff:254.157.241.86 is fully collapsed IPv6 dot decimal address'
    assert is_ipv6('fe80::204:61ff:254.157.241.86')

def test_uri1():
    'Uri parsed to dict.'
    uri = Uri('http://www.traxtech.com')
    assert uri.dict() == {'protocol': 'http', 'host': 'www.traxtech.com', 'port': 80}

def test_uri2():
    'Uri parsed returns to string.'
    uri = Uri('http://www.traxtech.com')
    assert str(uri) == 'http://www.traxtech.com'

def test_uri2a():
    'Uri.str classmethod returns strig.'
    opts = dict(
        protocol = 'https',
        username = 'dan',
        password = 'foo',
        host = 'www.traxtech.com',
        port = '8080',
        path = '/foo',
        inputs = dict(a=['1','2']),
        fragment = 'debian'
    )
    assert Uri.str(opts, username='mike') == 'https://mike:foo@www.traxtech.com:8080/foo?a=1&a=2#debian'

def test_uri3():
    'Uri parses all parts of a uri.'
    uri = Uri('http://dan:foo@www.traxtech.com:8080/bar/bang?a=1&b=2&b=3#shamwow')
    assert uri.protocol == 'http', 'Bad proto parse.'
    assert uri.username == 'dan', 'Bad user parse.'
    assert uri.password == 'foo', 'Bad pass parse.'
    assert uri.port == 8080, 'Bad port parse.'
    assert uri.path == '/bar/bang', 'Bad path parse.'
    assert uri.inputs == dict(a=['1'], b=['2','3']), 'Bad inputs parse.'
    assert uri.fragment == 'shamwow', 'Bad frag parse.'
    assert uri.host == 'www.traxtech.com'

def test_uri4():
    'Uri setters.'
    uri = Uri('https://')
    uri.host = 'www.traxtech.com'
    uri.protocol = 'http'
    assert uri.protocol == 'http', 'Bad protocol parse.'
    uri.username = 'dan'
    assert uri.username == 'dan', 'Bad user parse.'
    uri.password = 'foo'
    assert uri.password == 'foo', 'Bad pass parse.'
    uri.port = 8080
    assert uri.port == 8080, 'Bad port parse.'
    uri.path = '/bar/bang'
    assert uri.path == '/bar/bang', 'Bad path parse.'
    uri.inputs = dict(a='1', b=['2', '3'])
    assert uri.inputs == dict(a=['1'], b=['2','3']), 'Bad inputs parse.'
    uri.fragment = 'shamwow'
    assert uri.fragment == 'shamwow', 'Bad frag parse.'
    assert uri.host == 'www.traxtech.com'

def test_uri4a():
    'Uri setters ipv6 host.'
    uri = Uri('http://')
    uri.host = '2001:470:f16e:1::1'
    assert str(uri) == 'http://[2001:470:f16e:1::1]'

def test_uri5():
    'Uri handles files'
    uri = Uri('file:///root/foo')
    assert str(uri) == 'file:///root/foo'

def test_uri6():
    'Uri hasubdir and issubdir works as expected.'
    uri1 = Uri('http://www.traxtech.com/vuln/')
    uri2 = Uri('http://www.traxtech.com/vuln/child')
    assert uri1.haschild(uri2), 'assert1 - haschild is False instead of True.'
    assert uri2.ischild(uri1), 'assert2 - ischild is False instead of True.'
    assert not uri2.haschild(uri1), 'assert3 - haschild is True insteadof False.'
    assert not uri1.ischild(uri2), 'assert4 - ischild is True instead of False.'
    uri1 = Uri('http://www.traxtech.com/')
    uri2 = Uri('http://www.traxtech.com/vuln/child')
    assert uri1.haschild(uri2), 'assert5 - haschild is False instead of True.'
    assert uri2.ischild(uri1), 'assert6 - ischild is False instead of True.'
    assert not uri2.haschild(uri1), 'assert7 - haschild is True insteadof False.'
    assert not uri1.ischild(uri2), 'assert8 - ischild is True instead of False.'
    uri1 = Uri('http://www.traxtech.com/vuln')
    uri2 = Uri('http://www.traxtech.com/vuln/child')
    assert not uri1.haschild(uri2), 'assert9 - haschild is True instead of False.'
    assert not uri2.ischild(uri1), 'assert10 - ischild is True instead of False.'
    assert not uri2.haschild(uri1), 'assert11 - haschild is True instead of False.'
    assert not uri1.ischild(uri2), 'assert12 - ischild is True instead of False.'
    uri1 = Uri('http://www.traxtech.com:8080/')
    uri2 = Uri('http://www.traxtech.com/vuln/child')
    assert not uri1.haschild(uri2), 'assert13 - haschild is True instead of False.'
    assert not uri2.ischild(uri1), 'assert14 - ischild is True instead of False.'
    assert not uri2.haschild(uri1), 'assert15 - haschild is True instead of False.'
    assert not uri1.ischild(uri2), 'assert16 - ischild is True instead of False.'

def test_uri5():
    'relative link w/o trailing slash on base'
    uri = relative_uri('foo/bar', 'http://www.traxtech.com/bang')
    assert str(uri) == 'http://www.traxtech.com/foo/bar'

def test_uri5a():
    'relative link with trailing slah on base'
    uri = relative_uri('foo/bar', 'http://www.traxtech.com/bang/')
    assert str(uri) == 'http://www.traxtech.com/bang/foo/bar'

def test_uri5b():
    'relative link - relative from root'
    uri = relative_uri('/foo/bar', 'http://www.traxtech.com/bang/')
    assert str(uri) == 'http://www.traxtech.com/foo/bar'

def test_uri5c():
    'relative link with trailing slash and dot'
    uri = relative_uri('./foo/bar', 'http://www.traxtech.com/bang/')
    assert str(uri) == 'http://www.traxtech.com/bang/foo/bar'

def test_uri5d():
    'relative link without trailing slash and dog'
    uri = relative_uri('./foo/bar', 'http://www.traxtech.com/bang')
    assert str(uri) == 'http://www.traxtech.com/foo/bar'

def test_uri5e():
    'relative links traversal'
    uri = relative_uri('../../foo/bar', 'http://www.traxtech.com/bang/bam')
    assert str(uri) == 'http://www.traxtech.com/foo/bar'

def test_uri5f():
    'relative links up one'
    uri = relative_uri('../foo/bar', 'http://www.traxtech.com/bang/bam')
    assert str(uri) == 'http://www.traxtech.com/foo/bar'

def test_uri5g():
    'relative links up one with slash'
    uri = relative_uri('../foo/bar', 'http://www.traxtech.com/bang/bam/')
    assert str(uri) == 'http://www.traxtech.com/bang/foo/bar'

def uri5e():
    'Handle links relative to root'
    assert str(relative_uri('pages/', 'https://apt.traxtech.com')) == \
        'https://apt.traxtech.com/pages/'

def test_netloca():
    'Can parse credentials host and port of ipv6 host Uris.'
    uri = Uri('http://test:foo@[2001:470:f16e:1::1]:80/')
    credentials, host, port = uri.parse_netloc()
    assert credentials == 'test:foo', 'Bad credentials parse (a).'
    assert host == '2001:470:f16e:1::1', 'Bad host parse (a).'
    assert port == 80, 'Bad port parse (a).'

    uri = Uri('http://[2001:470:f16e:1::1]:80/')
    credentials, host, port = uri.parse_netloc()
    assert credentials == None, 'Bad credentials parse (b).'
    assert host == '2001:470:f16e:1::1', 'Bad host parse (b).'
    assert port == 80, 'Bad port parse (b).'

    uri = Uri('http://[2001:470:f16e:1::1]/')
    credentials, host, port = uri.parse_netloc()
    assert credentials == None, 'Bad credentials parse (c).'
    assert host == '2001:470:f16e:1::1', 'Bad host parse (c).'
    assert port == None, 'Bad port parse (c).'

def test_netlocb():
    'Can parse credentials host and port non ipv6 host Uris.'
    uri = Uri('http://test:foo@www.traxtech.com:80/')
    credentials, host, port = uri.parse_netloc()
    assert credentials == 'test:foo', 'Bad credentials parse (a).'
    assert host == 'www.traxtech.com', 'Bad host parse (a).'
    assert port == 80, 'Bad port parse (a).'

    uri = Uri('http://www.traxtech.com:80/')
    credentials, host, port = uri.parse_netloc()
    assert credentials == None, 'Bad credentials parse (b).'
    assert host == 'www.traxtech.com', 'Bad host parse (b).'
    assert port == 80, 'Bad port parse (b).'

    uri = Uri('http://www.traxtech.com/')
    credentials, host, port = uri.parse_netloc()
    assert credentials == None, 'Bad credentials parse (c).'
    assert host == 'www.traxtech.com', 'Bad host parse (c).'
    assert port == None, 'Bad port parse (c).'
