"""M2Crypto support for Python's httplib. 

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved."""

import string, sys
import socket
from urlparse import urlsplit, urlunsplit
import base64

from httplib import *
from httplib import HTTPS_PORT # This is not imported with just '*'
import SSL

class HTTPSConnection(HTTPConnection):

    """
    This class allows communication via SSL using M2Crypto.
    """

    default_port = HTTPS_PORT

    def __init__(self, host, port=None, strict=None, **ssl):
        self.session = None
        keys = ssl.keys()
        try: 
            keys.remove('key_file')
        except ValueError:
            pass
        try:
            keys.remove('cert_file')
        except ValueError:
            pass
        try:
            keys.remove('ssl_context')
        except ValueError:
            pass
        if keys:
            raise ValueError('unknown keyword argument')
        try:
            self.ssl_ctx = ssl['ssl_context']
            assert isinstance(self.ssl_ctx, SSL.Context), self.ssl_ctx
        except KeyError:
            self.ssl_ctx = SSL.Context('sslv23')
        HTTPConnection.__init__(self, host, port, strict)

    def connect(self):
        self.sock = SSL.Connection(self.ssl_ctx)
        if self.session:
            self.sock.set_session(self.session)
        self.sock.connect((self.host, self.port))

    def close(self):
        # This kludges around line 545 of httplib.py,
        # which closes the connection in this object;
        # the connection remains open in the response
        # object.
        #
        # M2Crypto doesn't close-here-keep-open-there,
        # so, in effect, we don't close until the whole 
        # business is over and gc kicks in.
        #
        # XXX Long-running callers beware leakage.
        #
        # XXX 05-Jan-2002: This module works with Python 2.2,
        # XXX but I've not investigated if the above conditions
        # XXX remain.
        pass
    
    def get_session(self):
        return self.sock.get_session()

    def set_session(self, session):
        self.session = session
        

class HTTPS(HTTP):
    
    _connection_class = HTTPSConnection

    def __init__(self, host='', port=None, strict=None, **ssl):
        HTTP.__init__(self, host, port, strict)
        try:
            self.ssl_ctx = ssl['ssl_context']
        except KeyError:
            self.ssl_ctx = SSL.Context('sslv23')
        assert isinstance(self._conn, HTTPSConnection)
        self._conn.ssl_ctx = self.ssl_ctx


class ProxyHTTPSConnection(HTTPSConnection):

    """
    An HTTPS Connection that uses a proxy and the CONNECT request.

    When the connection is initiated, CONNECT is first sent to the proxy (along
    with authorization headers, if supplied). If successful, an SSL connection
    will be established over the socket through the proxy and to the target
    host.

    Finally, the actual request is sent over the SSL connection tunneling
    through the proxy.
    """

    _ports = {'http' : 80, 'https' : 443}
    _AUTH_HEADER = "Proxy-Authorization"
    _UA_HEADER = "User-Agent"

    def __init__(self, host, port=None, strict=None, username=None,
        password=None, **ssl):
        """
        Create the ProxyHTTPSConnection object.

        host and port are the hostname and port number of the proxy server.
        """
        HTTPSConnection.__init__(self, host, port, strict, **ssl)

        self._username = username
        self._password = password
        self._proxy_auth = None
        self._proxy_UA = None

    def putrequest(self, method, url, skip_host=0, skip_accept_encoding=0):
        #putrequest is called before connect, so can interpret url and get
        #real host/port to be used to make CONNECT request to proxy
        proto, netloc, path, query, fragment = urlsplit(url)
        if not proto:
            raise ValueError, "unknown URL type: %s" % url
        
        #get host & port
        try:
            username_password, host_port = netloc.split('@')
        except ValueError:
            host_port = netloc

        try:
            host, port = host_port.split(':')
        except ValueError:
            host = host_port
            #try to get port from proto
            try:
                port = self._ports[proto]
            except KeyError:
                raise ValueError, "unknown protocol for: %s" % url

        self._real_host = host
        self._real_port = int(port)
        rest = urlunsplit((None, None, path, query, fragment))
        if sys.version_info < (2,4):
            HTTPSConnection.putrequest(self, method, rest, skip_host)
        else:
            HTTPSConnection.putrequest(self, method, rest, skip_host, skip_accept_encoding)

    def putheader(self, header, value):
        # Store the auth header if passed in.
        if header.lower() == self._UA_HEADER.lower():
            self._proxy_UA = value
        if header.lower() == self._AUTH_HEADER.lower():
            self._proxy_auth = value
        else:
            HTTPSConnection.putheader(self, header, value)

    def endheaders(self):
        # We've recieved all of hte headers. Use the supplied username
        # and password for authorization, possibly overriding the authstring
        # supplied in the headers.
        if not self._proxy_auth:
            self._proxy_auth = self._encode_auth()

        HTTPSConnection.endheaders(self)

    def connect(self):
        HTTPConnection.connect(self)

        #send proxy CONNECT request
        self.sock.sendall(self._get_connect_msg())
        response = HTTPResponse(self.sock)
        response.begin()
        
        code = response.status
        if code != 200:
            #proxy returned and error, abort connection, and raise exception
            self.close()
            raise socket.error, "Proxy connection failed: %d" % code
       
        self._start_ssl()

    def _get_connect_msg(self):
        """ Return an HTTP CONNECT request to send to the proxy. """
        msg = "CONNECT %s:%d HTTP/1.1\r\n" % (self._real_host, self._real_port)
        msg = msg + "Host: %s:%d\r\n" % (self._real_host, self._real_port)
        if self._proxy_UA:
            msg = msg + "%s: %s\r\n" % (self._UA_HEADER, self._proxy_UA)
        if self._proxy_auth:
            msg = msg + "%s: %s\r\n" % (self._AUTH_HEADER, self._proxy_auth) 
        msg = msg + "\r\n"
        return msg

    def _start_ssl(self):
        """ Make this connection's socket SSL-aware. """
        self.sock = SSL.Connection(self.ssl_ctx, self.sock)
        self.sock.setup_ssl()
        self.sock.set_connect_state()
        self.sock.connect_ssl()

    def _encode_auth(self):
        """ Encode the username and password for use in the auth header. """
        if not (self._username and self._password):
            return None
        # Authenticated proxy
        userpass = "%s:%s" % (self._username, self._password)
        enc_userpass = base64.encodestring(userpass).replace("\n", "")
        return "Basic %s" % enc_userpass
