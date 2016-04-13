"""
Make Twisted use M2Crypto for SSL

Copyright (c) 2004-2007 Open Source Applications Foundation.
All rights reserved.
"""

__all__ = ['connectSSL', 'connectTCP', 'listenSSL', 'listenTCP',
           'TLSProtocolWrapper']

import twisted.protocols.policies as policies
import twisted.internet.reactor
from twisted.protocols.policies import ProtocolWrapper
from twisted.internet.interfaces import ITLSTransport
from zope.interface import implements

import M2Crypto # for M2Crypto.BIO.BIOError
from M2Crypto import m2, X509
from M2Crypto.SSL import Checker


def _alwaysSucceedsPostConnectionCheck(peerX509, expectedHost):
    return 1


def connectSSL(host, port, factory, contextFactory, timeout=30,
               bindAddress=None,
               reactor=twisted.internet.reactor,
               postConnectionCheck=Checker.Checker()):
    """
    A convenience function to start an SSL/TLS connection using Twisted.
    
    See IReactorSSL interface in Twisted. 
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: \
        TLSProtocolWrapper(factory,
                           wrappedProtocol,
                           startPassThrough=0,
                           client=1,
                           contextFactory=contextFactory,
                           postConnectionCheck=postConnectionCheck)
    return reactor.connectTCP(host, port, wrappingFactory, timeout, bindAddress)
        

def connectTCP(host, port, factory, timeout=30, bindAddress=None,
               reactor=twisted.internet.reactor,
               postConnectionCheck=Checker.Checker()):
    """
    A convenience function to start a TCP connection using Twisted. 

    NOTE: You must call startTLS(ctx) to go into SSL/TLS mode.

    See IReactorTCP interface in Twisted. 
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: \
        TLSProtocolWrapper(factory,
                           wrappedProtocol,
                           startPassThrough=1,
                           client=1,
                           contextFactory=None,
                           postConnectionCheck=postConnectionCheck)
    return reactor.connectTCP(host, port, wrappingFactory, timeout, bindAddress)


def listenSSL(port, factory, contextFactory, backlog=5, interface='',
              reactor=twisted.internet.reactor,  
              postConnectionCheck=_alwaysSucceedsPostConnectionCheck):
    """
    A convenience function to listen for SSL/TLS connections using Twisted. 

    See IReactorSSL interface in Twisted. 
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: \
        TLSProtocolWrapper(factory,
                           wrappedProtocol,
                           startPassThrough=0,
                           client=0,
                           contextFactory=contextFactory,
                           postConnectionCheck=postConnectionCheck)
    return reactor.listenTCP(port, wrappingFactory, backlog, interface)


def listenTCP(port, factory, backlog=5, interface='',
              reactor=twisted.internet.reactor,  
              postConnectionCheck=None):
    """
    A convenience function to listen for TCP connections using Twisted. 
    
    NOTE: You must call startTLS(ctx) to go into SSL/TLS mode.

    See IReactorTCP interface in Twisted. 
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: \
        TLSProtocolWrapper(factory,
                           wrappedProtocol,
                           startPassThrough=1,
                           client=0,
                           contextFactory=None,
                           postConnectionCheck=postConnectionCheck)
    return reactor.listenTCP(port, wrappingFactory, backlog, interface)


class _BioProxy:
    """
    The purpose of this class is to eliminate the __del__ method from
    TLSProtocolWrapper, and thus letting it be garbage collected.
    """
    
    m2_bio_free_all = m2.bio_free_all

    def __init__(self, bio):
        self.bio = bio
        
    def _ptr(self):
        return self.bio
    
    def __del__(self):
        if self.bio is not None:
            self.m2_bio_free_all(self.bio)


class _SSLProxy:
    """
    The purpose of this class is to eliminate the __del__ method from
    TLSProtocolWrapper, and thus letting it be garbage collected.
    """
    
    m2_ssl_free = m2.ssl_free

    def __init__(self, ssl):
        self.ssl = ssl
        
    def _ptr(self):
        return self.ssl
    
    def __del__(self):
        if self.ssl is not None:
            self.m2_ssl_free(self.ssl)


class TLSProtocolWrapper(ProtocolWrapper):
    """
    A SSL/TLS protocol wrapper to be used with Twisted. Typically
    you would not use this class directly. Use connectTCP, 
    connectSSL, listenTCP, listenSSL functions defined above,
    which will hook in this class.
    """

    implements(ITLSTransport)
    
    def __init__(self, factory, wrappedProtocol, startPassThrough, client,
                 contextFactory, postConnectionCheck):
        """
        @param factory:
        @param wrappedProtocol:
        @param startPassThrough:    If true we won't encrypt at all. Need to
                                    call startTLS() later to switch to SSL/TLS.
        @param client:              True if this should be a client protocol.
        @param contextFactory:      Factory that creates SSL.Context objects.
                                    The called function is getContext().
        @param postConnectionCheck: The post connection check callback that
                                    will be called just after connection has
                                    been established but before any real data
                                    has been exchanged. The first argument to
                                    this function is an X509 object, the second
                                    is the expected host name string.
        """
        #ProtocolWrapper.__init__(self, factory, wrappedProtocol)
        #XXX: Twisted 2.0 has a new addition where the wrappingFactory is
        #     set as the factory of the wrappedProtocol. This is an issue
        #     as the wrap should be transparent. What we want is 
        #     the factory of the wrappedProtocol to be the wrappedFactory and
        #     not the outer wrappingFactory. This is how it was implemented in
        #     Twisted 1.3
        self.factory = factory
        self.wrappedProtocol = wrappedProtocol
        
        # wrappedProtocol == client/server instance
        # factory.wrappedFactory == client/server factory

        self.data = '' # Clear text to encrypt and send
        self.encrypted = '' # Encrypted data we need to decrypt and pass on
        self.tlsStarted = 0 # SSL/TLS mode or pass through
        self.checked = 0 # Post connection check done or not
        self.isClient = client
        self.helloDone = 0 # True when hello has been sent
        if postConnectionCheck is None:
            self.postConnectionCheck = _alwaysSucceedsPostConnectionCheck
        else:
            self.postConnectionCheck = postConnectionCheck

        if not startPassThrough:
            self.startTLS(contextFactory.getContext())
            
    def clear(self):
        """
        Clear this instance, after which it is ready for reuse.
        """
        if getattr(self, 'tlsStarted', 0):
            self.sslBio = None
            self.ssl = None
            self.internalBio = None
            self.networkBio = None
        self.data = ''
        self.encrypted = ''
        self.tlsStarted = 0
        self.checked = 0
        self.isClient = 1
        self.helloDone = 0
        # We can reuse self.ctx and it will be deleted automatically
        # when this instance dies
        
    def startTLS(self, ctx):
        """
        Start SSL/TLS. If this is not called, this instance just passes data
        through untouched.
        """
        # NOTE: This method signature must match the startTLS() method Twisted
        #       expects transports to have. This will be called automatically
        #       by Twisted in STARTTLS situations, for example with SMTP.
        if self.tlsStarted:
            raise Exception, 'TLS already started'

        self.ctx = ctx

        self.internalBio = m2.bio_new(m2.bio_s_bio())
        m2.bio_set_write_buf_size(self.internalBio, 0)
        self.networkBio = _BioProxy(m2.bio_new(m2.bio_s_bio()))
        m2.bio_set_write_buf_size(self.networkBio._ptr(), 0)
        m2.bio_make_bio_pair(self.internalBio, self.networkBio._ptr())

        self.sslBio = _BioProxy(m2.bio_new(m2.bio_f_ssl()))

        self.ssl = _SSLProxy(m2.ssl_new(self.ctx.ctx))

        if self.isClient:
            m2.ssl_set_connect_state(self.ssl._ptr())
        else:
            m2.ssl_set_accept_state(self.ssl._ptr())
            
        m2.ssl_set_bio(self.ssl._ptr(), self.internalBio, self.internalBio)
        m2.bio_set_ssl(self.sslBio._ptr(), self.ssl._ptr(), m2.bio_noclose)

        # Need this for writes that are larger than BIO pair buffers
        mode = m2.ssl_get_mode(self.ssl._ptr())
        m2.ssl_set_mode(self.ssl._ptr(),
                        mode |
                        m2.SSL_MODE_ENABLE_PARTIAL_WRITE |
                        m2.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)

        self.tlsStarted = 1

    def write(self, data):
        if not self.tlsStarted:
            ProtocolWrapper.write(self, data)
            return

        try:
            encryptedData = self._encrypt(data)
            ProtocolWrapper.write(self, encryptedData)
            self.helloDone = 1
        except M2Crypto.BIO.BIOError, e:
            # See http://www.openssl.org/docs/apps/verify.html#DIAGNOSTICS
            # for the error codes returned by SSL_get_verify_result.
            e.args = (m2.ssl_get_verify_result(self.ssl._ptr()), e.args[0])
            raise e

    def writeSequence(self, data):
        if not self.tlsStarted:
            ProtocolWrapper.writeSequence(self, ''.join(data))
            return

        self.write(''.join(data))

    def loseConnection(self):
        # XXX Do we need to do m2.ssl_shutdown(self.ssl._ptr())?
        ProtocolWrapper.loseConnection(self)

    def connectionMade(self):
        ProtocolWrapper.connectionMade(self)
        if self.tlsStarted and self.isClient and not self.helloDone:
            self._clientHello()

    def dataReceived(self, data):
        if not self.tlsStarted:
            ProtocolWrapper.dataReceived(self, data)
            return

        self.encrypted += data

        try:
            while 1:
                decryptedData = self._decrypt()

                self._check()

                encryptedData = self._encrypt()
                ProtocolWrapper.write(self, encryptedData)

                ProtocolWrapper.dataReceived(self, decryptedData)

                if decryptedData == '' and encryptedData == '':
                    break
        except M2Crypto.BIO.BIOError, e:
            # See http://www.openssl.org/docs/apps/verify.html#DIAGNOSTICS
            # for the error codes returned by SSL_get_verify_result.
            e.args = (m2.ssl_get_verify_result(self.ssl._ptr()), e.args[0])
            raise e

    def connectionLost(self, reason):
        self.clear()
        ProtocolWrapper.connectionLost(self, reason)

    def _check(self):
        if not self.checked and m2.ssl_is_init_finished(self.ssl._ptr()):
            x509 = m2.ssl_get_peer_cert(self.ssl._ptr())
            if x509 is not None:
                x509 = X509.X509(x509, 1)
            if self.isClient:
                host = self.transport.addr[0]
            else:
                host = self.transport.getPeer().host
            if not self.postConnectionCheck(x509, host):
                raise Checker.SSLVerificationError, 'post connection check'
            self.checked = 1

    def _clientHello(self):
        try:
            # We rely on OpenSSL implicitly starting with client hello
            # when we haven't yet established an SSL connection
            encryptedData = self._encrypt(clientHello=1)
            ProtocolWrapper.write(self, encryptedData)
            self.helloDone = 1
        except M2Crypto.BIO.BIOError, e:
            # See http://www.openssl.org/docs/apps/verify.html#DIAGNOSTICS
            # for the error codes returned by SSL_get_verify_result.
            e.args = (m2.ssl_get_verify_result(self.ssl._ptr()), e.args[0])
            raise e

    def _encrypt(self, data='', clientHello=0):
        # XXX near mirror image of _decrypt - refactor
        encryptedData = ''
        self.data += data
        # Optimizations to reduce attribute accesses
        sslBioPtr = self.sslBio._ptr()
        networkBio = self.networkBio._ptr()
        m2bio_ctrl_get_write_guarantee = m2.bio_ctrl_get_write_guarantee
        m2bio_write = m2.bio_write
        m2bio_should_retry = m2.bio_should_retry
        m2bio_ctrl_pending = m2.bio_ctrl_pending
        m2bio_read = m2.bio_read
        
        while 1:
            g = m2bio_ctrl_get_write_guarantee(sslBioPtr)
            if g > 0 and self.data != '' or clientHello:
                r = m2bio_write(sslBioPtr, self.data)
                if r <= 0:
                    assert(m2bio_should_retry(sslBioPtr))
                else:
                    assert(self.checked)               
                    self.data = self.data[r:]
                  
            pending = m2bio_ctrl_pending(networkBio)
            if pending:
                d = m2bio_read(networkBio, pending)
                if d is not None: # This is strange, but d can be None
                    encryptedData += d
                else:
                    assert(m2bio_should_retry(networkBio))
            else:
                break
        return encryptedData

    def _decrypt(self, data=''):
        # XXX near mirror image of _encrypt - refactor
        self.encrypted += data
        decryptedData = ''
        # Optimizations to reduce attribute accesses
        sslBioPtr = self.sslBio._ptr()
        networkBio = self.networkBio._ptr()
        m2bio_ctrl_get_write_guarantee = m2.bio_ctrl_get_write_guarantee
        m2bio_write = m2.bio_write
        m2bio_should_retry = m2.bio_should_retry
        m2bio_ctrl_pending = m2.bio_ctrl_pending
        m2bio_read = m2.bio_read
        
        while 1:
            g = m2bio_ctrl_get_write_guarantee(networkBio)
            if g > 0 and self.encrypted != '':
                r = m2bio_write(networkBio, self.encrypted)
                if r <= 0:
                    assert(m2bio_should_retry(networkBio))
                else:
                    self.encrypted = self.encrypted[r:]
                              
            pending = m2bio_ctrl_pending(sslBioPtr)
            if pending:
                d = m2bio_read(sslBioPtr, pending)
                if d is not None: # This is strange, but d can be None
                    decryptedData += d
                else:
                    assert(m2bio_should_retry(sslBioPtr))
            else:
                break

        return decryptedData
