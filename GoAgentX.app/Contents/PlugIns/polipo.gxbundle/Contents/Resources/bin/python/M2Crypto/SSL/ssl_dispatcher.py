"""SSL dispatcher

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

__all__ = ['ssl_dispatcher']

# Python
import asyncore, socket

# M2Crypto
from Connection import Connection
from M2Crypto import Err, m2


class ssl_dispatcher(asyncore.dispatcher):

    def create_socket(self, ssl_context):
        self.family_and_type=socket.AF_INET, socket.SOCK_STREAM
        self.ssl_ctx=ssl_context
        self.socket=Connection(self.ssl_ctx)
        #self.socket.setblocking(0)
        self.add_channel()

    def connect(self, addr):
        self.socket.setblocking(1)
        self.socket.connect(addr)
        self.socket.setblocking(0)

    def recv(self, buffer_size=4096):
        """Receive data over SSL."""
        return self.socket.recv(buffer_size)

    def send(self, buffer):
        """Send data over SSL."""
        return self.socket.send(buffer)

