import os
import shutil
import socket
import time
import tempfile

from smb.SMBConnection import SMBConnection

import pytest


@pytest.fixture(scope='session')
def aws_access_key_id():
    return os.environ.get('AWS_ACCESS_KEY_ID', '')


@pytest.fixture(scope='session')
def aws_secret_access_key():
    return os.environ.get('AWS_SECRET_ACCESS_KEY', '')


@pytest.fixture(scope='session')
def session_name(suffix='-traxcommon'):
    return tempfile.mkdtemp(suffix="{}{}".format(time.time(), suffix)).split('/')[-1]


@pytest.yield_fixture(scope='session')
def testdir(session_name):
    session_dir = '/tmp/{}'.format(session_name)
    os.makedirs(session_dir)
    yield session_dir
    shutil.rmtree(session_dir)


def _walk(conn, share, root):
    dirs = []
    files = []
    for a in conn.listPath(share, root):
        if a.filename in ['.', '..', ]:
            continue
        if a.isDirectory:
            dirs.append(a)
        else:
            files.append(a)
    return (root, [_.filename for _ in dirs], [_.filename for _ in files],)


def walk(conn, share, root, topdown=False):
    root, dirs, files = _walk(conn, share, root)
    if not topdown:
        yield root, dirs, files
    for dirname in dirs:
        for subdir, dirs, files in walk(conn, share, '{}\\{}'.format(root, dirname), topdown=topdown):
            yield subdir, dirs, files
    if topdown:
        yield root, dirs, files


@pytest.yield_fixture(scope='session')
def smbtestdir(session_name):
    fullname = 'fxb04fs0301.filex.com'
    ip = socket.gethostbyname(fullname)
    hostname, domain = fullname.split('.', 1)
    share = 'everyone'
    directory = '{}'.format(session_name)
    con = SMBConnection('', '', 'client', hostname)
    con.connect(ip)
    con.createDirectory(share, directory)
    con.close()
    yield fullname, share, directory
    con = SMBConnection('', '', 'client', hostname)
    con.connect(ip)
    for path, dirs, files in walk(con, share, directory, topdown=True):
        for filename in files:
            con.deleteFiles(share, '{}\\{}'.format(path, filename))
        con.deleteDirectory(share, path)
    con.close()
