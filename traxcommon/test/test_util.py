
from traxcommon.util import legacy_auth_url

def test_legacy_auth_url():
    class MockRequest:
        url = 'http://traxtech.com/bar'
        scheme = 'http'
    url = legacy_auth_url('https://auth.traxtech.com', MockRequest)
    assert url == 'https://auth.traxtech.com?secure=false&referrerUrl=traxtech.com%2Fbar'
