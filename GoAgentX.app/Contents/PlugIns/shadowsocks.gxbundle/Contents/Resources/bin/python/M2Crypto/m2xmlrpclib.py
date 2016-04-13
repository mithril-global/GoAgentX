"""M2Crypto enhancement to xmlrpclib.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

import base64, string, sys

from xmlrpclib import *
import M2Crypto
import SSL, httpslib, m2urllib

__version__ = M2Crypto.version

class SSL_Transport(Transport):

    user_agent = "M2Crypto_XMLRPC/%s - %s" % (__version__, Transport.user_agent)

    def __init__(self, ssl_context=None, *args, **kw):
        if getattr(Transport, '__init__', None) is not None:
            Transport.__init__(self, *args, **kw)
        if ssl_context is None:
            self.ssl_ctx=SSL.Context('sslv23')
        else:
            self.ssl_ctx=ssl_context

    def request(self, host, handler, request_body, verbose=0):
        # Handle username and password.
        user_passwd, host_port = m2urllib.splituser(host)
        _host, _port = m2urllib.splitport(host_port)
        h = httpslib.HTTPS(_host, int(_port), ssl_context=self.ssl_ctx)
        if verbose:
            h.set_debuglevel(1)

        # What follows is as in xmlrpclib.Transport. (Except the authz bit.)
        h.putrequest("POST", handler)

        # required by HTTP/1.1
        h.putheader("Host", _host)

        # required by XML-RPC
        h.putheader("User-Agent", self.user_agent)
        h.putheader("Content-Type", "text/xml")
        h.putheader("Content-Length", str(len(request_body)))

        # Authorisation.
        if user_passwd is not None:
            auth=string.strip(base64.encodestring(user_passwd))
            h.putheader('Authorization', 'Basic %s' % auth)

        h.endheaders()

        if request_body:
            h.send(request_body)

        errcode, errmsg, headers = h.getreply()

        if errcode != 200:
            raise ProtocolError(
                host + handler,
                errcode, errmsg,
                headers
                )

        self.verbose = verbose
        return self.parse_response(h.getfile())

