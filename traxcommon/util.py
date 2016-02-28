import binascii
import datetime
import os
import StringIO
import time
from six.moves import urllib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def legacy_auth_url(login_url, request):
    params = {'referrerUrl': request.url.split('/', 2)[2]}
    if request.scheme == 'https':
        params['secure'] = 'true'
    else:
        params['secure'] = 'false'
    redirurl = "{}?{}".format(
        login_url, urllib.urlencode(params)
    )
    return "{}?{}".format(
        login_url, urllib.urlencode(params)
    )


class LegacyToken(object):

    def __init__(self, user_id, user_name, email, first_name, last_name,
            full_name, impersonator, org_id, org_name, login_at, preferences=None):
        self.user_id = user_id
        self.user_name = user_name
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.full_name = full_name
        self.impersonator = impersonator
        self.org_id = org_id
        self.org_name = org_name
        if login_at:
            self.login_at = int(login_at)
        else:
            self.login_at = None
        self.preferences = preferences or []

    def to_string(self):
        return '|-|'.join(
            [
                self.user_id, self.user_name, self.email, self.first_name,
                self.last_name, self.full_name, self.impersonator, self.org_id,
                self.org_name, str(self.login_at)
            ] + self.preferences
        )

    @property
    def login_datetime(self):
        if self.login_at:
            return datetime.datetime.fromtimestamp(self.login_at)

    @classmethod
    def from_token_string(cls, token):
        return cls(*cls.split_token_string(token))

    @staticmethod
    def split_token_string(token):
        return [_ for _ in token.split('|') if _ != '-']

    @classmethod
    def from_fxs_user(cls, user, org, impname=''):
        utcnow = datetime.datetime.utcnow()
        epoch = int(time.mktime(utcnow.timetuple()))
        return cls(
            user.name, user.fxsEntityName, user.fxsEmail, user.fxsFirstName,
            user.fxsLastName, user.fxsFullName, impname, org.name,
            org.fxsEntityName, epoch
        )


class PKCS7Encoder(object):
    '''
    RFC 2315: PKCS#7 page 21
    Some content-encryption algorithms assume the
    input length is a multiple of k octets, where k > 1, and
    let the application define a method for handling inputs
    whose lengths are not a multiple of k octets. For such
    algorithms, the method shall be to pad the input at the
    trailing end with k - (l mod k) octets all having value k -
    (l mod k), where l is the length of the input. In other
    words, the input is padded at the trailing end with one of
    the following strings:

             01 -- if l mod k = k-1
            02 02 -- if l mod k = k-2
                        .
                        .
                        .
          k k ... k k -- if l mod k = 0

    The padding can be removed unambiguously since all input is
    padded and no padding string is a suffix of another. This
    padding method is well-defined if and only if k < 256;
    methods for larger k are an open issue for further study.
    '''
    def __init__(self, k=16):
        self.k = k

    def decode(self, text):
        '''
        Remove the PKCS#7 padding from a text string

        @param text The padded text for which the padding is to be removed.

        @exception ValueError Raised when the input padding is missing or corrupt.
        '''
        nl = len(text)
        val = int(binascii.hexlify(text[-1]), 16)
        if val > self.k:
            raise ValueError('Input is not padded or padding is corrupt')

        l = nl - val
        return text[:l]

    def encode(self, text):
        '''
        Pad an input string according to PKCS#7

        @param text The text to encode.
        '''
        l = len(text)
        output = StringIO.StringIO()
        val = self.k - (l % self.k)
        for _ in xrange(val):
            output.write('%02x' % val)
        return text + binascii.unhexlify(output.getvalue())


def Xencode_aes_pkcs7(raw_data, key, iv_size=16):
    from Crypto.Cipher import AES
    iv = generate_iv(iv_size)
    encoder = PKCS7Encoder()
    pad_text = encoder.encode(raw_data)
    aes = AES.new(key, AES.MODE_CBC, iv)
    return binascii.hexlify(iv + aes.encrypt(pad_text))


def encode_aes_pkcs7(raw_data, key, iv_size=16):
    backend = default_backend()
    iv = generate_iv(iv_size)
    padder = padding.PKCS7(128).padder()
    pad_text = padder.update(raw_data)
    pad_text += padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = binascii.hexlify(iv + encryptor.update(pad_text) + encryptor.finalize())
    return ct


def Xdecode_aes_pkcs7(crypdata, key, iv_size=16):
    from Crypto.Cipher import AES
    bindata = binascii.unhexlify(crypdata)
    iv = bindata[:iv_size]
    cipher = bindata[iv_size:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    pkdecoder = PKCS7Encoder()
    return pkdecoder.decode(aes.decrypt(cipher))


def decode_aes_pkcs7(crypdata, key, iv_size=16):
    backend = default_backend()
    bindata = binascii.unhexlify(crypdata)
    iv = bindata[:iv_size]
    ct = bindata[iv_size:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    pad_text = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(pad_text)
    return data + unpadder.finalize()


def generate_iv(size):
    """
    Get random bytes of a certian length making sure no null bytes are
    included.
    """
    iv_size = 0
    iv = ''
    while iv_size < size:
        randbytes = os.urandom(size).replace('\x00', '')
        iv += randbytes
        iv_size = len(iv)
    return iv[:size]
