# -*- coding: utf-8 -*
from __future__ import absolute_import, unicode_literals, print_function

import pytest
from .fixtures import *

from urlio.url import *

SMB_BASE = 'smb://filex.com/it/stg/static_tests'
S3_BASE = 's3://traxtech-testbucket-internal'


@pytest.yield_fixture
def tmpfile():
    stemp = tempfile.mktemp()
    urltemp = 'file://{}'.format(stemp)
    with open(stemp, 'wb') as fp:
        fp.write(urltemp.encode())
    print("{} {}".format(stemp, urltemp))
    yield urltemp
    os.remove(stemp)

@pytest.yield_fixture
def smbtmpfile():
    stemp = tempfile.mktemp(dir='')
    smbtmp = '{}/{}'.format(SMB_BASE, stemp)
    print(smbtmp)
    fp = SMBUrl(
        smbtmp,
        mode='wb',
    )
    fp.write(smbtmp.encode())
    fp.close()
    yield smbtmp
    SMBUrl(smbtmp).remove()

@pytest.yield_fixture
def s3tmpfile():
    stemp = tempfile.mktemp(dir='')
    s3tmp = '{}/{}'.format(S3_BASE, stemp)
    fp = S3Url(
        s3tmp,
        mode='wb',
    )
    fp.write(s3tmp.encode())
    fp.close()
    yield s3tmp
    S3Url(s3tmp).remove()


def test_local_url():
    a = LocalUrl('file:///tmp/foo.txt')
    instance_attrs = dir(a)
    # iobase_expected_attrs = [
    #     'atime', 'basename', 'close', 'closed', 'ctime', 'dirname', 'dirnames',
    #     'dirs', 'exists', 'filenames', 'fileno', 'files', 'flush', 'fp',
    #     'isatty', 'isdir', 'join', 'ls', 'ls_names', 'makedirs', 'mode',
    #     'mtime', 'read', 'readable', 'readline', 'readlines', 'remove',
    #     'rename', 'rmtree', 'seek', 'seekable', 'size', 'stat', 'static_join',
    #     'tell', 'truncate', 'writable', 'write', 'writelines',
    # ]
    expected_attrs = [
        'atime', 'basename', 'close', 'ctime', 'dirname', 'dirnames', 'dirs',
        'exists', 'filenames', 'fp', 'isdir', 'join', 'ls', 'ls_names',
        'makedirs', 'mode', 'mtime', 'read',  'readline', 'readlines',
        'remove', 'rename', 'rmtree', 'seek', 'size', 'stat', 'static_join',
        'tell',  'write',
    ]
    for i in expected_attrs:
        assert i in instance_attrs


def test_local_url_a():
    a = LocalUrl('file://localhost/foo.txt')


def test_local_uri_no_path():
    with pytest.raises(Exception):
        LocalUrl('file://foo.txt')


def test_local_url_read_write_bytes(testdir):
    file = 'file://{}/{}'.format(testdir, 'local_url_write.txt')
    a = LocalUrl(file, 'wb')
    testbytes = b'test write'
    a.write(testbytes)
    a = LocalUrl(file, 'rb')
    assert a.read() == testbytes

def test_local_url_join():
    expected = 'file;//tmp/foo/bar/bang'
    LocalUrl('file://tmp/foo').join('bar', 'bang').url == expected

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_smb_url_read_write_bytes(smbtestdir):
    fullname, share, path = smbtestdir
    testbytes = b'test write'
    basepath = 'smb://fxb04fs0301.filex.com/everyone/{}'.format(path.replace('\\', '/'))
    file = '{}/{}'.format(basepath, 'smb_url_read_write_bytes.txt')
    a = SMBUrl(file, 'wb')
    a.write(testbytes)
    a = SMBUrl(file, 'rb')
    assert a.read() == testbytes


@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_smb_url_exists(smbtestdir):
    fullname, share, path = smbtestdir
    testbytes = b'test write'
    basepath = 'smb://fxb04fs0301.filex.com/everyone/{}'.format(path.replace('\\', '/'))
    file = '{}/{}'.format(basepath, 'smb_url_exits.txt')
    a = SMBUrl(file, mode='wb')
    assert not a.exists()
    a = SMBUrl(file, mode='wb')
    a.write(testbytes)
    assert a.exists()


def test_smb_url_repr():
    a = SMBUrl('smb://filex.com/it/stg/test.txt', mode='wb')
    s = repr(a)
    assert s.startswith('<SMBUrl(\'smb://filex.com/it/stg/test.txt\', mode=\'wb\')')


def test_smb_url_join_a():
    url = SMBUrl('smb://fxb04fs0301.filex.com/everyone')
    joined_url = url.join('foo.txt')
    assert joined_url.uri == 'smb://fxb04fs0301.filex.com/everyone/foo.txt'

def test_smb_url_join_b():
    url = SMBUrl('smb://fxb04fs0301.filex.com/everyone')
    joined_url = url.join('foo', 'bar.txt')
    assert joined_url.uri == 'smb://fxb04fs0301.filex.com/everyone/foo/bar.txt'

def test_smb_url_join_c():
    asciiurl = b'smb://fxb04fs0301.filex.com/everyone'.decode('ascii')
    url = SMBUrl(asciiurl)
    joined_url = url.join('foo', 'クール.txt')
    assert joined_url.uri == 'smb://fxb04fs0301.filex.com/everyone/foo/クール.txt'

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_s3_url_instantiation():
    s3 = S3Url('s3://traxtech-testbucket-internal/test', 'wb')
    testbytes = b'test write'
    s3.write(testbytes)
    s3.close()
    s3 = S3Url('s3://traxtech-testbucket-internal/test', 'rb')
    assert s3.read() == testbytes

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_url_fr78():
    u = SMBUrl(
        "smb://filex.com/it/stg/static_tests/test_smbc_read/test.txt",
    )
    s = u.read(None)
    assert len(s) == 10, len(s)
    assert s == b'Nice test.', s

def test_local_url___str__():
    smb_path = LocalUrl('file:///tmp/foo')
    assert str(smb_path) == 'file:///tmp/foo'

def test_smb_url___str__():
    smb_path = SMBUrl('smb://smb1.s03.filex.com/it/stg')
    assert str(smb_path) == 'smb://smb1.s03.filex.com/it/stg'

def test_wrap_local_url_in_io_wrappers(tmpfile):
    print(tmpfile)
    pth = LocalUrl(tmpfile, mode='rb')
    fp = io.TextIOWrapper(pth)
    assert fp.read() == tmpfile

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_wrap_smb_url_in_io_wrappers(smbtmpfile):
    pth = SMBUrl(
        smbtmpfile,
        mode='rb',
    )
    fp = io.TextIOWrapper(pth)
    assert fp.read() == smbtmpfile

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_wrap_s3_url_in_io_wrappers(s3tmpfile):
    pth = S3Url(
        s3tmpfile,
        mode='rb',
    )
    fp = io.TextIOWrapper(pth)
    assert fp.read() == s3tmpfile
