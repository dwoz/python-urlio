import os
import datetime
from traxcommon import path
from traxcommon.path import Path, SMBPath, LocalPath, smb_dirname

BASE = '\\\\filex.com\\it\\stg\\static_tests'

if 'SMBUSER' in os.environ:
    path.SMB_USER = os.environ['SMBUSER']
if 'SMBPASS' in os.environ:
    path.SMB_PASS = os.environ['SMBPASS']


def teardown_module():
    dirname = "{}\\{}".format(BASE, 'test_chunk_write')
    for filename in path.Path(dirname).filenames():
        path.Path(filename).remove()
    p = path.Path(r'\\fxb01fs0300.filex.com\FileRouterTest\test_chunk_write\test.txt')
    if p.exists():
        p.remove()


def data_path(filename):
    return os.path.join(os.path.dirname(__file__), 'data', filename)


def test_path():
    path = Path(data_path('empty_file'))
    assert path.tell() == 0


def find_dfs_share(path, api=None):
    path = path.replace('\\\\filex.com\\it\\stg\\', '')
    return (
        'fxb04fs0301',
        'filerouter_stage',
        'filex.com',
        path,
    )


def test_smbpath1():
    """
    Call find_dfs method to lookup dfs information
    """
    p = SMBPath(
        '\\\\filex.com\\it\\stg\\meh',
        find_dfs_share=find_dfs_share
    )
    assert p.domain == 'filex.com'
    assert p.server_name == 'fxb04fs0301'
    assert p.share == 'filerouter_stage'
    assert p.relpath == 'meh', "{}".format(p.relpath)


def test_pysmb_smbpath1():
    """
    Call find_dfs method to lookup dfs information
    """
    p = SMBPath(
        '\\\\filex.com\\it\\stg\\foo\\bar',
        find_dfs_share=find_dfs_share
    )
    assert p.domain == 'filex.com'
    assert p.server_name == 'fxb04fs0301'
    assert p.share == 'filerouter_stage'
    assert p.relpath == 'foo\\bar', "{}".format(p.relpath)

def test_smbpath2():
    """
    List files in an smb directory
    """
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smbpath2'),
        find_dfs_share=find_dfs_share
    )
    expect = [
        "{0}\\{1}".format(BASE, 'test_smbpath2\\one'),
        "{0}\\{1}".format(BASE, 'test_smbpath2\\two'),
    ]
    files = [i.path for i in p.files()]
    assert expect == files, "expect={} files={}".format(expect, files)


def test_path3():
    path = SMBPath(
        "{0}\\{1}".format(BASE, "test_smbpath3\\test_file"),
        find_dfs_share=find_dfs_share
    )
    s = path.read()
    assert s == 'This is a small test file', s


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
        find_dfs_share=find_dfs_share
    ).basename == 'bar'
    assert SMBPath(
        '\\foo\\bar',
        find_dfs_share=find_dfs_share
    ).basename == 'bar'
    assert SMBPath(
        '\\foo\\',
        find_dfs_share=find_dfs_share
    ).basename == 'foo'
    assert SMBPath(
        '\\foo',
        find_dfs_share=find_dfs_share
    ).basename == 'foo'
    assert SMBPath(
        '\\',
        find_dfs_share=find_dfs_share
    ).basename == '\\'


def test_smbpath_exists():
    BASE = '\\\\filex.com\\it\\stg\\static_tests'
    path = SMBPath(
        "{0}\\{1}".format(BASE, "test_smbexists1\\test_file"),
        find_dfs_share=find_dfs_share
    )
    assert path.exists()

def test_local_path_files():
    os.makedirs('/tmp/test_local_path_files')
    P1 = '/tmp/test_local_path_files/foo.xml'
    P2 = '/tmp/test_local_path_files/foo.txt'
    with open(P2, 'w') as fp:
        fp.write('foo.txt')
    with open(P1, 'w') as fp:
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


def test_smb_remove():
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_remove\\testfile'),
        mode='w',
        find_dfs_share=find_dfs_share
    )
    p.write('this is a test file')
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_remove\\testfile'),
        find_dfs_share=find_dfs_share
    )
    assert p.exists()
    p.remove()
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_remove\\testfile'),
        find_dfs_share=find_dfs_share
    )
    assert not p.exists()

def test_smb_mkdirs():
    """
    SMBPath.makedirs
    """
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_mkdirs\\foo\\bar'),
        mode='w',
        find_dfs_share=find_dfs_share
    )
    if p.exists():
        p.remove()
    assert not p.exists()
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_mkdirs\\foo'),
        mode='w',
        find_dfs_share=find_dfs_share
    )
    if p.exists():
        p.remove()
    assert not p.exists()
    p.makedirs(is_dir=True)
    assert p.exists()
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_mkdirs\\foo\\bar'),
        mode='w',
        find_dfs_share=find_dfs_share
    )
    if p.exists():
        p.remove()
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smb_mkdirs\\foo'),
        mode='w',
        find_dfs_share=find_dfs_share
    )
    if p.exists():
        p.remove()

def test_ls_glob():
    """
    List directory contents and filter on glob
    """
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_ls_names'),
        mode='r',
        find_dfs_share=find_dfs_share
    )
    for i in p.ls_names('ab*'):
        assert i in [
            "{}\\{}\\{}".format(BASE, 'test_ls_names', 'abcd'),
            "{}\\{}\\{}".format(BASE, 'test_ls_names', 'abef'),
        ]
        assert i not in [
            "{}\\{}\\{}".format(BASE, 'test_ls_names', 'defg'),
        ]

def test_read():
    """
    test pysmb read
    """
    p = SMBPath(
        "{}\\{}\\{}".format(BASE, 'test_smbc_read', 'test.txt'),
        mode='r',
        find_dfs_share=find_dfs_share
    )
    p.tell() == 0
    a = p.read(5)
    index = p.tell()
    assert index == 5, index
    assert a == 'Nice ', a
    a = p.read(4)
    index = p.tell()
    assert index == 9, index
    assert a == 'test', a

def test_size():
    p = SMBPath(
        "{}\\{}\\{}".format(BASE, 'test_smbc_read', 'test.txt'),
        mode='r',
        find_dfs_share=find_dfs_share
    )
    assert p.size == 10, p.size

def test_mtime():
    p = SMBPath(
        "{}\\{}\\{}".format(BASE, 'test_smbc_read', 'test.txt'),
        mode='r',
        find_dfs_share=find_dfs_share
    )
    assert (
        p.mtime == datetime.datetime(2014, 10, 29, 3, 17, 15, 825794)
    ), p.mtime


def test_atime():
    p = SMBPath(
        "{}\\{}\\{}".format(BASE, 'test_smbc_read', 'test.txt'),
        mode='r',
        find_dfs_share=find_dfs_share
    )
    assert (
        p.atime == datetime.datetime(2015, 3, 29, 10, 20, 44, 209107)
    ), p.atime

def test_stat_2003():
    p = path.Path(r'\\fxb01fs0300.filex.com\FileRouterTest\stat_test\test.txt')
    stat = p.stat()
    assert stat['atime'] == datetime.datetime(2014, 12, 23, 21, 0, 51, 924522), stat['atime']

def test_chunk_write_2003():
    fpath = r'\\fxb01fs0300.filex.com\FileRouterTest\chunk_write\test.txt'
    p = path.Path(fpath, 'w')
    p.write('foo')
    p.write('bar')
    p = path.Path(fpath)
    rslt = p.read()
    assert rslt == 'foobar', rslt

def test_chunk_write_2008():
    p = SMBPath(
        "{}\\{}\\{}".format(BASE, 'test_chunk_write', 'test.txt'),
        mode='w',
        find_dfs_share=find_dfs_share
    )
    p.write('foo')
    p.write('bar')
    p = SMBPath(
        "{}\\{}\\{}".format(BASE, 'test_chunk_write', 'test.txt'),
        mode='r',
        find_dfs_share=find_dfs_share
    )
    rslt = p.read()
    assert rslt == 'foobar', rslt

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
def test_recurse():
    p = path.Path(r'\\filex.com\it\stg\static_tests\test_recurse')
    result = list(p.recurse())
    assert result == RECURSE_VALS, result

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
def test_recurse_files():
    p = path.Path(r'\\filex.com\it\stg\static_tests\test_recurse')
    result = list(p.recurse_files())
    assert result == RECURSE_FILES_VALS, result
