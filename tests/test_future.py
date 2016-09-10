from __future__ import unicode_literals
import os
from traxcommon import path
from traxcommon.path import SMBPath

import pytest
BASE = '\\\\filex.com\\it\\stg\\static_tests'
if 'SMBUSER' in os.environ:
    path.SMB_USER = os.environ['SMBUSER']
if 'SMBPASS' in os.environ:
    path.SMB_PASS = os.environ['SMBPASS']

def mock_find_dfs_share(path, api=None):
    path = path.replace('\\\\filex.com\\it\\stg\\', '')
    return (
        'fxb04fs0301',
        'filerouter_stage',
        'filex.com',
        path,
    )


@pytest.mark.skipif(not pytest.config.getvalue('network'), reason='--network was not specifified')
def test_smb_write():
    path = SMBPath(
        "{0}\\{1}".format(BASE, "test_smbpath3\\test_file"),
        find_dfs_share=mock_find_dfs_share
    )
    s = path.read()
    assert s == b'This is a small test file', s

