# -*- coding: utf-8 -*
from __future__ import absolute_import, print_function, unicode_literals
import binascii
import datetime
import hashlib
import sys
import io
import shutil
import os
import errno
import tempfile
from urlio import path
from urlio.dfs import find_dfs_share, FindDfsShare
from urlio.path import (
    PathFactory, SMBPath, LocalPath, smb_dirname, getBIOSName, OperationFailure
)

from .fixtures import data_path
import pytest

BASE = '\\\\filex.com\\it\\stg\\static_tests'

if 'SMBUSER' in os.environ:
    path.SMB_USER = os.environ['SMBUSER']
if 'SMBPASS' in os.environ:
    path.SMB_PASS = os.environ['SMBPASS']

Path = PathFactory()

def teardown_module():
    if not pytest.config.getvalue('network'):
        return
    dirname = "{}\\{}".format(BASE, 'test_chunk_write')
    Path = PathFactory()
    for filename in Path(dirname).filenames():
        if Path(filename).exists():
            Path(filename).remove()
    #p = Path(r'\\fxb01fs0300.filex.com\FileRouterTest\test_chunk_write\test.txt')
    #if p.exists():
    #    p.remove()


def mock_find_dfs_share(path, api=None):
    path = path.replace('\\\\filex.com\\it\\stg\\', '')
    return (
        'fxb04fs0301',
        'filerouter_stage',
        'filex.com',
        path,
    )

def test_find_dfs_share_a():
    rslt = find_dfs_share('\\\\filex.com\\Comm')
    assert rslt == ('fxs02fs0100', 'Comm', 'filex.com', '')

def test_find_dfs_share_b():
    try:
        rslt = find_dfs_share('\\\\filex.com\\comm', case_sensative=True)
    except FindDfsShare as e:
        assert e.args[0] == "No dfs cache result found"
        return
    assert False, "no excption raised"

def test_find_dfs_share_c():
    rslt = find_dfs_share('\\\\Filex.com\\Comm')
    assert rslt == ('fxs02fs0100', 'Comm', 'filex.com', '')

def test_find_dfs_share_d():
    rslt = find_dfs_share('\\\\Filex.com\\Comm', case_sensative=True)
    assert rslt == ('FXB01FS0300', 'Comm', 'filex.com', '')

def test_find_dfs_share_d():
    try:
        rslt = find_dfs_share('\\\\Filex.com\\comm', case_sensative=True)
    except FindDfsShare as e:
        assert e.args[0] == "No dfs cache result found"
        return
    assert False, "no excption raised"

def test_find_dfs_share_e():
    rslt = find_dfs_share('\\\\Filex.com\\Comm\\Foo', case_sensative=True)
    assert rslt == ('fxs02fs0100', 'Comm', 'filex.com', 'Foo'), rslt

def test_find_dfs_share_f():
    rslt = find_dfs_share('\\\\FXESB01.Filex.com\\Comm\\Foo', case_sensative=True)
    assert rslt == ('fxesb01', 'Comm', 'filex.com', 'Foo'), rslt

def test_find_dfs_share_g():
    rslt = find_dfs_share('\\\\filex.com\\Comm\\AS2\\Other', case_sensative=True)
    assert rslt == ('fxb05fs0300', 'AS2', 'filex.com', 'Other'), rslt

def test_find_dfs_share_h():
    rslt = find_dfs_share('\\\\filex.com\\Comm\\AS2\\Other\\Foo\\bar.txt', case_sensative=True)
    assert rslt == ('fxb05fs0300', 'AS2', 'filex.com', 'Other\\Foo\\bar.txt'), rslt

def test_find_dfs_share_i():
    rslt = find_dfs_share('\\\\filex.com\\Comm\\DDS Bad Packs\\bar.jpeg', case_sensative=True)
    assert rslt == ('FXB05FS0300', 'DDSFTP', 'filex.com', 'BadPacks\\bar.jpeg'), rslt

def test_patha():
    Path = PathFactory()
    path = Path(data_path('empty_file'))
    assert path.tell() == 0


def test_smbpath1():
    """
    Call find_dfs method to lookup dfs information
    """
    p = SMBPath(
        '\\\\filex.com\\it\\stg\\meh',
        find_dfs_share=mock_find_dfs_share
    )
    assert p.domain == 'filex.com'
    assert p.server_name == 'fxb04fs0301'
    assert p.share == 'filerouter_stage'
    assert p.relpath == 'meh', "{}".format(p.relpath)

def test_path_case_preservation():
    spath = '\\\\filex.com\\Comm\\Bar\\BanG.txt'
    assert SMBPath(spath).path == spath

def test_pysmb_smbpath1():
    """
    Call find_dfs method to lookup dfs information
    """
    p = SMBPath(
        '\\\\filex.com\\it\\stg\\foo\\bar',
        find_dfs_share=mock_find_dfs_share
    )
    assert p.domain == 'filex.com'
    assert p.server_name == 'fxb04fs0301'
    assert p.share == 'filerouter_stage'
    assert p.relpath == 'foo\\bar', "{}".format(p.relpath)

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_smbpath2():
    """
    List files in an smb directory
    """
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smbpath2'),
        find_dfs_share=mock_find_dfs_share
    )
    expect = [
        "{0}\\{1}".format(BASE, 'test_smbpath2\\one'),
        "{0}\\{1}".format(BASE, 'test_smbpath2\\two'),
    ]
    files = [i.path for i in p.files()]
    assert expect == files, "expect={} files={}".format(expect, files)


@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_path3():
    path = SMBPath(
        "{0}\\{1}".format(BASE, "test_smbpath3\\test_file"),
        find_dfs_share=mock_find_dfs_share
    )
    s = path.read()
    assert s == b'This is a small test file', s


def test_localpath_dirname1():
    assert LocalPath('/foo/bar').dirname == '/foo'
    assert LocalPath('/foo/').dirname == '/'
    assert LocalPath('/foo').dirname == '/'


def test_localpath_basename1():
    assert LocalPath('/foo/bar/').basename == 'bar'
    assert LocalPath('/foo/bar').basename == 'bar'
    assert LocalPath('/foo/').basename == 'foo'
    assert LocalPath('/foo').basename == 'foo'
    assert LocalPath('/').basename == '/'


def test_smbpath_dirname1():
    assert smb_dirname(
        '\\\\filex.com\\foo\\bar',
    ) == '\\\\filex.com\\foo'
    assert smb_dirname(
        '\\foo\\bar',
    ) == '\\foo', '\\foo\\bar, {}'.format(smb_dirname('\\foo\\bar'))
    assert smb_dirname(
        '\\foo\\',
    ) == '\\', '\\foo\\, {}'.format(smb_dirname('\\foo\\'))
    assert smb_dirname(
        '\\foo',
    ) == '\\', '\\foo, {}'.format(smb_dirname('\\foo'))
    assert smb_dirname(
        'wk_group.mdb'
    ) == '.', 'workgroup.mdb, {}'.format(smb_dir('wk_group.mdb'))


def test_smbpath_basename1():
    assert SMBPath(
        '\\foo\\bar\\',
        find_dfs_share=mock_find_dfs_share
    ).basename == 'bar'
    assert SMBPath(
        '\\foo\\bar',
        find_dfs_share=mock_find_dfs_share
    ).basename == 'bar'
    assert SMBPath(
        '\\foo\\',
        find_dfs_share=mock_find_dfs_share
    ).basename == 'foo'
    assert SMBPath(
        '\\foo',
        find_dfs_share=mock_find_dfs_share
    ).basename == 'foo'
    assert SMBPath(
        '\\',
        find_dfs_share=mock_find_dfs_share
    ).basename == '\\'


@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_smbpath_exists():
    BASE = '\\\\filex.com\\it\\stg\\static_tests'
    path = SMBPath(
        "{0}\\{1}".format(BASE, "test_smbexists1\\test_file"),
        find_dfs_share=mock_find_dfs_share
    )
    assert path.exists()

def test_local_path_files():
    os.makedirs('/tmp/test_local_path_files')
    P1 = '/tmp/test_local_path_files/foo.xml'
    P2 = '/tmp/test_local_path_files/foo.txt'
    with io.open(P2, 'w') as fp:
        fp.write('foo.txt')
    with io.open(P1, 'w') as fp:
        fp.write('foo.xml')
    try:
        p = LocalPath('/tmp/test_local_path_files')
        l = []
        for a in p.files():
            l.append(a.path)
        assert P1 in l
        assert P2 in l
        l = []
        for a in p.files('*.txt'):
            l.append(a.path)
        assert P1 not in l
        assert P2 in l
    finally:
        os.remove('/tmp/test_local_path_files/foo.txt')
        os.remove('/tmp/test_local_path_files/foo.xml')
        os.rmdir('/tmp/test_local_path_files')


@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_smb_remove():
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_remove\\testfile'),
        mode='w',
        find_dfs_share=mock_find_dfs_share
    )
    p.write('this is a test file'.encode('utf-8'))
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_remove\\testfile'),
        find_dfs_share=mock_find_dfs_share
    )
    assert p.exists()
    p.remove()
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_remove\\testfile'),
        find_dfs_share=mock_find_dfs_share
    )
    assert not p.exists()

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_smb_mkdirs():
    """
    SMBPath.makedirs
    """
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_mkdirs\\foo\\bar'),
        mode='w',
        find_dfs_share=mock_find_dfs_share
    )
    if p.exists():
        p.remove()
    assert not p.exists()
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_mkdirs\\foo'),
        mode='w',
        find_dfs_share=mock_find_dfs_share
    )
    if p.exists():
        p.remove()
    assert not p.exists()
    p.makedirs(is_dir=True)
    assert p.exists()
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_mkdirs\\foo\\bar'),
        mode='w',
        find_dfs_share=mock_find_dfs_share
    )
    if p.exists():
        p.remove()
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_mkdirs\\foo'),
        mode='w',
        find_dfs_share=mock_find_dfs_share
    )
    if p.exists():
        p.remove()

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_ls_glob():
    """
    List directory contents and filter on glob
    """
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_ls_names'),
        mode='r',
        find_dfs_share=mock_find_dfs_share
    )
    for i in p.ls_names('ab*'):
        assert i in [
            "{}\\{}\\{}".format(BASE, 'test_ls_names', 'abcd'),
            "{}\\{}\\{}".format(BASE, 'test_ls_names', 'abef'),
        ]
        assert i not in [
            "{}\\{}\\{}".format(BASE, 'test_ls_names', 'defg'),
        ]

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_read():
    """
    test pysmb read
    """
    p = SMBPath(
        "{}\\{}\\{}".format(BASE, 'test_smbc_read', 'test.txt'),
        mode='r',
        find_dfs_share=mock_find_dfs_share
    )
    p.tell() == 0
    a = p.read(5)
    index = p.tell()
    assert index == 5, index
    assert a == b'Nice ', a
    a = p.read(4)
    index = p.tell()
    assert index == 9, index
    assert a == b'test', a

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_size():
    p = SMBPath(
        "{}\\{}\\{}".format(BASE, 'test_smbc_read', 'test.txt'),
        mode='r',
        find_dfs_share=mock_find_dfs_share
    )
    assert p.size == 10, p.size

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_mtime():
    p = SMBPath(
        "{}\\{}\\{}".format(BASE, 'test_smbc_read', 'test.txt'),
        mode='r',
        find_dfs_share=mock_find_dfs_share
    )
    expect = datetime.datetime(2014, 10, 29, 3, 17, 15, 825794)
    if sys.version_info >= (3,) and sys.platform != 'darwin':
        expect = datetime.datetime(2014, 10, 29, 3, 17, 15, 825793)
    assert (
        p.mtime == expect
    ), (p.mtime, expect)


@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_atime():
    p = SMBPath(
        "{}\\{}\\{}".format(BASE, 'test_smbc_read', 'test.txt'),
        mode='r',
        find_dfs_share=mock_find_dfs_share
    )
    assert (
        p.atime == datetime.datetime(2015, 3, 29, 10, 20, 44, 209107)
    ), p.atime

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_stat_2003():
    p = Path(r'\\fxb02fs0300.filex.com\Filerouter test\stat_test\test.txt')
    stat = p.stat()
    assert stat['atime'] == datetime.datetime(2016, 2, 21, 3, 31, 56, 288246), stat['atime']
    #assert stat['atime'] == datetime.datetime(2014, 12, 23, 21, 0, 51, 924522), stat['atime']

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_chunk_write_2003():
    fpath = r'\\fxb02fs0300.filex.com\Filerouter Test\chunk_write\test.txt'
    p = Path(fpath, 'w')
    p.write(b'foo')
    p.write(b'bar')
    p = Path(fpath)
    rslt = p.read()
    assert rslt == b'foobar', rslt

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_chunk_write_2008():
    p = SMBPath(
        "{}\\{}\\{}".format(BASE, 'test_chunk_write', 'test.txt'),
        mode='w',
        find_dfs_share=mock_find_dfs_share
    )
    p.write(b'foo')
    p.write(b'bar')
    p = SMBPath(
        "{}\\{}\\{}".format(BASE, 'test_chunk_write', 'test.txt'),
        mode='r',
        find_dfs_share=mock_find_dfs_share
    )
    rslt = p.read()
    assert rslt == b'foobar', rslt

RECURSE_VALS = [
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\doc1.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\doc2.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\doc3.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub1',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub1\\doc1.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub1\\doc2.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub2',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub2\\doc1.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub3',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub3\\doc1.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub3\\dubsub1',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub3\\dubsub1\\doc1.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub3\\dubsub1\\doc2.txt',
]

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_recurse():
    p = Path(r'\\filex.com\it\stg\static_tests\test_recurse')
    result = list(p.recurse())
    assert result == RECURSE_VALS, result

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_recurse_offset():
    p = Path(r'\\filex.com\it\stg\static_tests\test_recurse')
    result = list(p.recurse(offset=2))
    assert result == RECURSE_VALS[2:], result


RECURSE_FILES_VALS = [
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\doc1.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\doc2.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\doc3.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub1\\doc1.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub1\\doc2.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub2\\doc1.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub3\\doc1.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub3\\dubsub1\\doc1.txt',
    '\\\\filex.com\\it\\stg\\static_tests\\test_recurse\\sub3\\dubsub1\\doc2.txt',
]

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_recurse_files():
    p = Path(r'\\filex.com\it\stg\static_tests\test_recurse')
    result = list(p.recurse_files())
    assert result == RECURSE_FILES_VALS, result

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_list_empty():
    p = Path(r'\\filex.com\it\stg\static_tests\empty')
    l = list(p.ls())
    assert not l


@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_list_files_empty():
    p = Path(r'\\fxb02fs0300.filex.com\Filerouter Test\static_test\empty')
    #p = Path(r'\\filex.com\it\stg\static_tests\empty')
    l = list(p.filenames())
#    assert not l

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
@pytest.mark.skipif(not pytest.config.getvalue('slow'), reason='--slow was not specifified')
def test_large_file_2003():
    p = Path(r'\\fxb02fs0300.filex.com\Filerouter Test\large_file.txt', 'w')
    if p.exists():
        p.remove()
    whsh = hashlib.md5()
    rhsh = hashlib.md5()
    _ = binascii.hexlify(os.urandom(1000 * 1000 * 200))
    whsh.update(_)
    p.write(_)
    p = Path(r'\\fxb02fs0300.filex.com\Filerouter Test\large_file.txt')
    while True:
        _ = p.read(1000 * 1000 * 20)
        if not _:
            break
        rhsh.update(_)
    w = whsh.hexdigest()
    r = rhsh.hexdigest()
    assert w == r, (w, r)


@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
@pytest.mark.skipif(not pytest.config.getvalue('slow'), reason='--slow was not specifified')
def test_large_file_samba():
    p = Path(r'\\smb1.s03.filex.com\ftp\Apple\test\large_test_file.txt', 'w')
    if p.exists():
        p.remove()
    whsh = hashlib.md5()
    rhsh = hashlib.md5()
    _ = binascii.hexlify(os.urandom(1000 * 1000 * 200))
    whsh.update(_)
    p.write(_)
    p = Path(r'\\smb1.s03.filex.com\ftp\Apple\test\large_test_file.txt')
    while True:
        _ = p.read(1000 * 1000 * 20)
        if not _:
            break
        rhsh.update(_)
    w = whsh.hexdigest()
    r = rhsh.hexdigest()
    assert w == r, (w, r)

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
@pytest.mark.skipif(not pytest.config.getvalue('slow'), reason='--slow was not specifified')
def test_large_file_2008():
    p = Path(r'\\filex.com\it\stg\large_test_file.txt', 'w')
    if p.exists():
        p.remove()
    whsh = hashlib.md5()
    rhsh = hashlib.md5()
    _ = binascii.hexlify(os.urandom(1000 * 1000 * 200))
    whsh.update(_)
    p.write(_)
    p = Path(r'\\filex.com\it\stg\large_test_file.txt')
    while True:
        _ = p.read(1000 * 1000 * 20)
        if not _:
            break
        rhsh.update(_)
    w = whsh.hexdigest()
    r = rhsh.hexdigest()
    assert w == r, (w, r)

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
@pytest.mark.xfail(reason='UDP Netbios blocked')
def test_netbios_lookup():
    a = getBIOSName('205.159.43.10')
    assert a == 'FXDC0001', '{} != {}'.format(a, 'FXDC0001')


@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_bad_netbios_server():
    p = Path(r'\\fxcebfs0300.filex.com\Data Entry\Images')
    assert p.exists()


def test_local_unicode_file_stdlib():
    with io.open(data_path('שנוכל לבדוק עם.txt'), 'rb') as fp:
        data = fp.read()
    assert type(data) == bytes

def test_local_unicode_file():
    p = Path(data_path('שנוכל לבדוק עם.txt'))
    data = p.read()

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_smb_write_from_unicode_file():
    filename = 'שנוכל לבדוק עם.txt'
    with io.open(data_path(filename), 'rb') as fp:
        data = fp.read()
    p = Path(r'\\filex.com\it\stg\{}'.format(filename), 'w')
    p.write(data)
    p = Path(r'\\filex.com\it\stg\{}'.format(filename), 'r')
    assert data == p.read()
    assert type(data) == bytes

def test_smb_join():
    p = SMBPath('\\\\filex.com\\it\\stg\\a', find_dfs_share=mock_find_dfs_share)
    assert p.join('b', 'c', 'd').path == '\\\\filex.com\\it\\stg\\a\\b\\c\\d'
    p = SMBPath('\\\\filex.com\\it\\stg\\a\\', find_dfs_share=mock_find_dfs_share)
    assert p.join('b', 'c', 'd').path == '\\\\filex.com\\it\\stg\\a\\b\\c\\d'
    p = SMBPath('\\\\filex.com\\it\\stg\\a', find_dfs_share=mock_find_dfs_share)
    assert p.join('b', '\\c\\', '\\d').path == '\\\\filex.com\\it\\stg\\a\\b\\c\\d'

def test_local_join():
    assert LocalPath('/tmp/a').join('b', 'c', 'd').path == '/tmp/a/b/c/d'
    assert LocalPath('/tmp/a/').join('b', 'c', 'd').path == '/tmp/a/b/c/d'
    assert LocalPath('/tmp/a/').join('b/', '/c', '/d/').path == '/tmp/a/b/c/d'


@pytest.yield_fixture
def tmp_path():
    def makedirs(path, exist_ok=False):
        try:
            os.makedirs(path)
        except OSError as exc:
            if exc.errno == errno.EEXIST and os.path.isdir(path) and exist_ok:
                pass
            else:
                raise
    tmp = tempfile.mkdtemp()
    makedirs(tmp, exist_ok=True)
    yield tmp
    shutil.rmtree(tmp)

def test_local_makdirs(tmp_path):
    path = LocalPath(tmp_path).join('foo').path
    p = LocalPath(path)
    assert not p.exists()
    p.makedirs(is_dir=True)
    assert p.exists()
    with pytest.raises(OSError):
        p.makedirs(is_dir=True)
    try:
        p.makedirs(is_dir=True, exist_ok=True)
    except OSError:
        pytest.fail("Unexpected OSError")

@pytest.yield_fixture
def tmp_smb():
    BASE = '\\\\filex.com\\it\\stg\\static_tests'
    if not Path(BASE).exists():
        raise Exception("Unexpected condition")
    tmp = tempfile.mkdtemp().rsplit('/', 1)[-1]
    p = Path(BASE).join(tmp)
    p.makedirs(is_dir=True)
    if not p.exists():
        raise Exception("Unexpected condition")
    yield p.path
    for _, dirs, files in p.walk(top_down=True):
        for d in dirs:
            if d.exists():
                d.remove()
        for f in files:
            f.remove()
        _.remove()

@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_smb_makedirs(tmp_smb):
    path = SMBPath(tmp_smb).join('foo').path
    p = SMBPath(path)
    assert not p.exists()
    p.makedirs(is_dir=True)
    assert p.exists()
    with pytest.raises(OperationFailure):
        p.makedirs(is_dir=True)
    try:
        p.makedirs(is_dir=True, exist_ok=True)
    except OperationFailure:
        pytest.fail("Unexpected OperationFailure")
    try:
        p.join('bar', 'bang').makedirs(is_dir=True)
    except OperationFailure:
        pytest.fail("Unexpected OperationFailure")
