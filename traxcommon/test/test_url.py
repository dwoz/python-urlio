from ..url import Url, relative_url, is_ipv6

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

def test_url1():
    'Url parsed to dict.'
    url = Url('http://www.traxtech.com')
    assert url.dict() == {'protocol': 'http', 'host': 'www.traxtech.com', 'port': 80}

def test_url2():
    'Url parsed returns to string.'
    url = Url('http://www.traxtech.com')
    assert str(url) == 'http://www.traxtech.com'

def test_url2a():
    'Url.str classmethod returns strig.'
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
    assert Url.str(opts, username='mike') == 'https://mike:foo@www.traxtech.com:8080/foo?a=1&a=2#debian'

def test_url3():
    'Url parses all parts of a url.'
    url = Url('http://dan:foo@www.traxtech.com:8080/bar/bang?a=1&b=2&b=3#shamwow')
    assert url.protocol == 'http', 'Bad proto parse.'
    assert url.username == 'dan', 'Bad user parse.'
    assert url.password == 'foo', 'Bad pass parse.'
    assert url.port == 8080, 'Bad port parse.'
    assert url.path == '/bar/bang', 'Bad path parse.'
    assert url.inputs == dict(a=['1'], b=['2','3']), 'Bad inputs parse.'
    assert url.fragment == 'shamwow', 'Bad frag parse.'
    assert url.host == 'www.traxtech.com'

def test_url4():
    'Url setters.'
    url = Url('https://')
    url.host = 'www.traxtech.com'
    url.protocol = 'http'
    assert url.protocol == 'http', 'Bad protocol parse.'
    url.username = 'dan'
    assert url.username == 'dan', 'Bad user parse.'
    url.password = 'foo'
    assert url.password == 'foo', 'Bad pass parse.'
    url.port = 8080
    assert url.port == 8080, 'Bad port parse.'
    url.path = '/bar/bang'
    assert url.path == '/bar/bang', 'Bad path parse.'
    url.inputs = dict(a='1', b=['2', '3'])
    assert url.inputs == dict(a=['1'], b=['2','3']), 'Bad inputs parse.'
    url.fragment = 'shamwow'
    assert url.fragment == 'shamwow', 'Bad frag parse.'
    assert url.host == 'www.traxtech.com'

def test_url4a():
    'Url setters ipv6 host.'
    url = Url('http://')
    url.host = '2001:470:f16e:1::1'
    assert str(url) == 'http://[2001:470:f16e:1::1]'

def test_url5():
    'Url handles files'
    url = Url('file:///root/foo')
    assert str(url) == 'file:///root/foo'

def test_url6():
    'Url hasubdir and issubdir works as expected.'
    url1 = Url('http://www.traxtech.com/vuln/')
    url2 = Url('http://www.traxtech.com/vuln/child')
    assert url1.haschild(url2), 'assert1 - haschild is False instead of True.'
    assert url2.ischild(url1), 'assert2 - ischild is False instead of True.'
    assert not url2.haschild(url1), 'assert3 - haschild is True insteadof False.'
    assert not url1.ischild(url2), 'assert4 - ischild is True instead of False.'
    url1 = Url('http://www.traxtech.com/')
    url2 = Url('http://www.traxtech.com/vuln/child')
    assert url1.haschild(url2), 'assert5 - haschild is False instead of True.'
    assert url2.ischild(url1), 'assert6 - ischild is False instead of True.'
    assert not url2.haschild(url1), 'assert7 - haschild is True insteadof False.'
    assert not url1.ischild(url2), 'assert8 - ischild is True instead of False.'
    url1 = Url('http://www.traxtech.com/vuln')
    url2 = Url('http://www.traxtech.com/vuln/child')
    assert not url1.haschild(url2), 'assert9 - haschild is True instead of False.'
    assert not url2.ischild(url1), 'assert10 - ischild is True instead of False.'
    assert not url2.haschild(url1), 'assert11 - haschild is True instead of False.'
    assert not url1.ischild(url2), 'assert12 - ischild is True instead of False.'
    url1 = Url('http://www.traxtech.com:8080/')
    url2 = Url('http://www.traxtech.com/vuln/child')
    assert not url1.haschild(url2), 'assert13 - haschild is True instead of False.'
    assert not url2.ischild(url1), 'assert14 - ischild is True instead of False.'
    assert not url2.haschild(url1), 'assert15 - haschild is True instead of False.'
    assert not url1.ischild(url2), 'assert16 - ischild is True instead of False.'

def test_url5():
    'relative link w/o trailing slash on base'
    url = relative_url('foo/bar', 'http://www.traxtech.com/bang')
    assert str(url) == 'http://www.traxtech.com/foo/bar'

def test_url5a():
    'relative link with trailing slah on base'
    url = relative_url('foo/bar', 'http://www.traxtech.com/bang/')
    assert str(url) == 'http://www.traxtech.com/bang/foo/bar'

def test_url5b():
    'relative link - relative from root'
    url = relative_url('/foo/bar', 'http://www.traxtech.com/bang/')
    assert str(url) == 'http://www.traxtech.com/foo/bar'

def test_url5c():
    'relative link with trailing slash and dot'
    url = relative_url('./foo/bar', 'http://www.traxtech.com/bang/')
    assert str(url) == 'http://www.traxtech.com/bang/foo/bar'

def test_url5d():
    'relative link without trailing slash and dog'
    url = relative_url('./foo/bar', 'http://www.traxtech.com/bang')
    assert str(url) == 'http://www.traxtech.com/foo/bar'

def test_url5e():
    'relative links traversal'
    url = relative_url('../../foo/bar', 'http://www.traxtech.com/bang/bam')
    assert str(url) == 'http://www.traxtech.com/foo/bar'

def test_url5f():
    'relative links up one'
    url = relative_url('../foo/bar', 'http://www.traxtech.com/bang/bam')
    assert str(url) == 'http://www.traxtech.com/foo/bar'

def test_url5g():
    'relative links up one with slash'
    url = relative_url('../foo/bar', 'http://www.traxtech.com/bang/bam/')
    assert str(url) == 'http://www.traxtech.com/bang/foo/bar'

def url5e():
    'Handle links relative to root'
    assert str(relative_url('pages/', 'https://apt.traxtech.com')) == \
        'https://apt.traxtech.com/pages/'

def test_netloca():
    'Can parse credentials host and port of ipv6 host Urls.'
    url = Url('http://test:foo@[2001:470:f16e:1::1]:80/')
    credentials, host, port = url.parse_netloc()
    assert credentials == 'test:foo', 'Bad credentials parse (a).'
    assert host == '2001:470:f16e:1::1', 'Bad host parse (a).'
    assert port == 80, 'Bad port parse (a).'

    url = Url('http://[2001:470:f16e:1::1]:80/')
    credentials, host, port = url.parse_netloc()
    assert credentials == None, 'Bad credentials parse (b).'
    assert host == '2001:470:f16e:1::1', 'Bad host parse (b).'
    assert port == 80, 'Bad port parse (b).'

    url = Url('http://[2001:470:f16e:1::1]/')
    credentials, host, port = url.parse_netloc()
    assert credentials == None, 'Bad credentials parse (c).'
    assert host == '2001:470:f16e:1::1', 'Bad host parse (c).'
    assert port == None, 'Bad port parse (c).'

def test_netlocb():
    'Can parse credentials host and port non ipv6 host Urls.'
    url = Url('http://test:foo@www.traxtech.com:80/')
    credentials, host, port = url.parse_netloc()
    assert credentials == 'test:foo', 'Bad credentials parse (a).'
    assert host == 'www.traxtech.com', 'Bad host parse (a).'
    assert port == 80, 'Bad port parse (a).'

    url = Url('http://www.traxtech.com:80/')
    credentials, host, port = url.parse_netloc()
    assert credentials == None, 'Bad credentials parse (b).'
    assert host == 'www.traxtech.com', 'Bad host parse (b).'
    assert port == 80, 'Bad port parse (b).'

    url = Url('http://www.traxtech.com/')
    credentials, host, port = url.parse_netloc()
    assert credentials == None, 'Bad credentials parse (c).'
    assert host == 'www.traxtech.com', 'Bad host parse (c).'
    assert port == None, 'Bad port parse (c).'
