import os
from traxcommon import path
from traxcommon.path import Path, SMBPath, LocalPath, smb_dirname

if 'SMBUSER' in os.environ:
    path.SMB_USER = os.environ['SMBUSER']
if 'SMBPASS' in os.environ:
    path.SMB_PASS = os.environ['SMBPASS']

def data_path(filename):
    return os.path.join(os.path.dirname(__file__), 'data', filename)


def test_path():
    path = Path(data_path('empty_file'))
    assert path.tell() == 0


def find_dfs_share(path, api=None):
    path = path.replace('\\\\filex.com\\it\\longtermarchivebackup\\', '')
    return (
        'fxb04fs0301',
        'Long Term Archive Backup',
        'filex.com',
        path,
    )


def test_smbpath1():
    """
    Call find_dfs method to lookup dfs information
    """
    path = SMBPath(
        '\\\\filex.com\\it\\longtermarchivebackup\\staging\\meh',
        find_dfs_share=find_dfs_share
    )
    assert path.domain == 'filex.com'
    assert path.server_name == 'fxb04fs0301'
    assert path.share == 'Long Term Archive Backup'
    assert path.relpath == 'staging\\meh', "{}".format(path.relpath)


def test_smbpath2():
    """
    List files in an smb directory
    """
    BASE = '\\\\filex.com\\it\\longtermarchivebackup\\staging\\static_tests'
    p = SMBPath(
        "{0}\\{1}".format(BASE, 'test_smbpath2'),
        find_dfs_share=find_dfs_share
    )
    expect = [
        "{0}\\{1}".format(BASE, 'test_smbpath2\\one'),
        "{0}\\{1}".format(BASE, 'test_smbpath2\\two'),
    ]
    # Cast iterator to list
    files = list(p.files())
    assert expect == files, "expect={} files={}".format(expect, files)


def test_path3():
    BASE = '\\\\filex.com\\it\\longtermarchivebackup\\staging\\static_tests'
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
    BASE = '\\\\filex.com\\it\\longtermarchivebackup\\staging\\static_tests'
    path = SMBPath(
        "{0}\\{1}".format(BASE, "test_smbexists1\\test_file"),
        find_dfs_share=find_dfs_share
    )
    assert path.exists()
