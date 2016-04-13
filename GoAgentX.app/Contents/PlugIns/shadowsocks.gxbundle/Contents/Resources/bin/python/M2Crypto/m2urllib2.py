"""
M2Crypto enhancement to Python's urllib2 for handling 
'https' url's.

Code from urllib2 is Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007
Python Software Foundation; All Rights Reserved

Summary of changes:
 - Use an HTTPSProxyConnection if the request is going through a proxy.
 - Add the SSL context to the https connection when performing https_open.
 - Add the M2Crypto HTTPSHandler when building a default opener.
"""

import socket
from urllib2 import *
import urlparse

import SSL
import httpslib


class _closing_fileobject(socket._fileobject):
    '''socket._fileobject that propagates self.close() to the socket.

    Python 2.5 provides this as socket._fileobject(sock, close=True).
    '''

    def __init__(self, sock):
        socket._fileobject.__init__(self, sock)

    def close(self):
        sock = self._sock
        socket._fileobject.close(self)
        sock.close()

class HTTPSHandler(AbstractHTTPHandler):
    def __init__(self, ssl_context = None):
        AbstractHTTPHandler.__init__(self)

        if ssl_context is not None:
            assert isinstance(ssl_context, SSL.Context), ssl_context
            self.ctx = ssl_context
        else:
            self.ctx = SSL.Context()

    # Copied from urllib2, so we can set the ssl context.
    def https_open(self, req):
        """Return an addinfourl object for the request, using http_class.

        http_class must implement the HTTPConnection API from httplib.
        The addinfourl return value is a file-like object.  It also
        has methods and attributes including:
            - info(): return a mimetools.Message object for the headers
            - geturl(): return the original request URL
            - code: HTTP status code
        """
        host = req.get_host()
        if not host:
            raise URLError('no host given')

        # Our change: Check to see if we're using a proxy.
        # Then create an appropriate ssl-aware connection.
        full_url = req.get_full_url() 
        target_host = urlparse.urlparse(full_url)[1]

        if (target_host != host):
            h = httpslib.ProxyHTTPSConnection(host = host, ssl_context = self.ctx)
        else:
            h = httpslib.HTTPSConnection(host = host, ssl_context = self.ctx)
        # End our change
        h.set_debuglevel(self._debuglevel)

        headers = dict(req.headers)
        headers.update(req.unredirected_hdrs)
        # We want to make an HTTP/1.1 request, but the addinfourl
        # class isn't prepared to deal with a persistent connection.
        # It will try to read all remaining data from the socket,
        # which will block while the server waits for the next request.
        # So make sure the connection gets closed after the (only)
        # request.
        headers["Connection"] = "close"
        try:
            h.request(req.get_method(), req.get_selector(), req.data, headers)
            r = h.getresponse()
        except socket.error, err: # XXX what error?
            raise URLError(err)

        # Pick apart the HTTPResponse object to get the addinfourl
        # object initialized properly.

        # Wrap the HTTPResponse object in socket's file object adapter
        # for Windows.  That adapter calls recv(), so delegate recv()
        # to read().  This weird wrapping allows the returned object to
        # have readline() and readlines() methods.

        # XXX It might be better to extract the read buffering code
        # out of socket._fileobject() and into a base class.

        r.recv = r.read
        fp = _closing_fileobject(r)

        resp = addinfourl(fp, r.msg, req.get_full_url())
        resp.code = r.status
        resp.msg = r.reason
        return resp

        
    https_request = AbstractHTTPHandler.do_request_


# Copied from urllib2 with modifications for ssl
def build_opener(ssl_context = None, *handlers):
    """Create an opener object from a list of handlers.

    The opener will use several default handlers, including support
    for HTTP and FTP.

    If any of the handlers passed as arguments are subclasses of the
    default handlers, the default handlers will not be used.
    """
    import types
    def isclass(obj):
        return isinstance(obj, types.ClassType) or hasattr(obj, "__bases__")

    opener = OpenerDirector()
    default_classes = [ProxyHandler, UnknownHandler, HTTPHandler,
                       HTTPDefaultErrorHandler, HTTPRedirectHandler,
                       FTPHandler, FileHandler, HTTPErrorProcessor]
    skip = []
    for klass in default_classes:
        for check in handlers:
            if isclass(check):
                if issubclass(check, klass):
                    skip.append(klass)
            elif isinstance(check, klass):
                skip.append(klass)
    for klass in skip:
        default_classes.remove(klass)

    for klass in default_classes:
        opener.add_handler(klass())

    # Add the HTTPS handler with ssl_context
    if HTTPSHandler not in skip:
        opener.add_handler(HTTPSHandler(ssl_context))


    for h in handlers:
        if isclass(h):
            h = h()
        opener.add_handler(h)
    return opener
