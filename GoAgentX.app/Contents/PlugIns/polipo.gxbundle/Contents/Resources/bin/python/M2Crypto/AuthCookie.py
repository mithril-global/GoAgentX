"""Secure Authenticator Cookies

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

# M2Crypto
import Rand, m2

# Python. Cookie is bundled with Python 2.x. 
import Cookie, binascii, re, time


_MIX_FORMAT = 'exp=%s&data=%s&digest='
_MIX_RE     = re.compile('exp=(\d+\.\d+)&data=(.+)&digest=(\S*)')

def mix(expiry, data, format=_MIX_FORMAT):
    return format % (repr(expiry), data)

def unmix(dough, regex=_MIX_RE):
    mo = regex.match(dough)
    if mo:
        return float(mo.group(1)), mo.group(2)
    else:
        return None

def unmix3(dough, regex=_MIX_RE):
    mo = regex.match(dough)
    if mo:
        return float(mo.group(1)), mo.group(2), mo.group(3)
    else:
        return None


_TOKEN = '_M2AUTH_'

class AuthCookieJar:

    _keylen = 20

    def __init__(self):
        self._key = Rand.rand_bytes(self._keylen)
    
    def _hmac(self, key, data):
        return binascii.b2a_base64(m2.hmac(key, data, m2.sha1()))[:-1]
        
    def makeCookie(self, expiry, data):
        dough = mix(expiry, data)
        return AuthCookie(expiry, data, dough, self._hmac(self._key, dough))

    def isGoodCookie(self, cookie):
        assert isinstance(cookie, AuthCookie)
        if cookie.isExpired():
            return 0
        c = self.makeCookie(cookie._expiry, cookie._data)
        return (c._expiry == cookie._expiry) \
            and (c._data == cookie._data) \
            and (c._mac == cookie._mac) \
            and (c.output() == cookie.output())

    def isGoodCookieString(self, cookie_str):
        c = Cookie.SmartCookie()        
        c.load(cookie_str)
        if not c.has_key(_TOKEN):
            return 0
        undough = unmix3(c[_TOKEN].value)
        if undough is None:
            return 0
        exp, data, mac = undough
        c2 = self.makeCookie(exp, data)
        return (not c2.isExpired()) and (c2._mac == mac)


class AuthCookie:
    
    def __init__(self, expiry, data, dough, mac):
        self._expiry = expiry
        self._data = data
        self._mac = mac
        self._cookie = Cookie.SmartCookie()
        self._cookie[_TOKEN] = '%s%s' % (dough, mac)
        self._name = '%s%s' % (dough, mac)  # XXX WebKit only.

    def expiry(self):
        """Return the cookie's expiry time."""
        return self._expiry

    def data(self):
        """Return the data portion of the cookie."""
        return self._data

    def mac(self):
        """Return the cookie's MAC."""
        return self._mac

    def output(self):
        """Return the cookie's output in "Set-Cookie" format."""
        return self._cookie.output()

    def value(self):
        """Return the cookie's output minus the "Set-Cookie: " portion.
        """
        return self._cookie[_TOKEN].value

    def isExpired(self):
        """Return 1 if the cookie has expired, 0 otherwise."""
        return (time.time() > self._expiry)

    # XXX Following methods are for WebKit only. These should be pushed 
    # to WKAuthCookie.
    def name(self):
        return self._name

    def headerValue(self):
        return self.value()

