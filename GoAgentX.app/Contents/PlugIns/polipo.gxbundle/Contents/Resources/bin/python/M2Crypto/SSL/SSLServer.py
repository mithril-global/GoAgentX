"""SSLServer

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

__all__ = ['SSLServer', 'ForkingSSLServer', 'ThreadingSSLServer']

# Python
import socket, SocketServer

# M2Crypto
from Connection import Connection
from M2Crypto.SSL import SSLError
from M2Crypto import m2


class SSLServer(SocketServer.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, ssl_context, bind_and_activate=True):
        """ 
        Superclass says: Constructor. May be extended, do not override.
        This class says: Ho-hum.
        """
        SocketServer.BaseServer.__init__(self, server_address, RequestHandlerClass)
        self.ssl_ctx=ssl_context
        self.socket=Connection(self.ssl_ctx)
        if bind_and_activate:
            self.server_bind()
            self.server_activate()        

    def handle_request(self):
        request = None
        client_address = None
        try:
            request, client_address = self.get_request()
            if self.verify_request(request, client_address):
                self.process_request(request, client_address)
        except SSLError:
            self.handle_error(request, client_address)

    def handle_error(self, request, client_address):
        print '-'*40
        import traceback
        traceback.print_exc()
        print '-'*40


class ForkingSSLServer(SocketServer.ForkingMixIn, SSLServer):
    pass


class ThreadingSSLServer(SocketServer.ThreadingMixIn, SSLServer):
    pass


