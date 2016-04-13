"""M2Crypto wrapper for OpenSSL Error API.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

import BIO
import m2

def get_error():
    err=BIO.MemoryBuffer()
    m2.err_print_errors(err.bio_ptr())
    return err.getvalue()

def get_error_code():
    return m2.err_get_error()

def peek_error_code():
    return m2.err_peek_error()

def get_error_lib(err):
    return m2.err_lib_error_string(err)

def get_error_func(err):
    return m2.err_func_error_string(err)

def get_error_reason(err):
    return m2.err_reason_error_string(err)

def get_x509_verify_error(err):
    return m2.x509_get_verify_error(err)

class SSLError(Exception):
    def __init__(self, err, client_addr):
        self.err = err
        self.client_addr = client_addr

    def __str__(self):
        if (isinstance(self.client_addr, unicode)):
            s = self.client_addr.encode('utf8')
        else:
            s = self.client_addr
        return "%s: %s: %s" % \
            (m2.err_func_error_string(self.err), \
            s, \
            m2.err_reason_error_string(self.err))

class M2CryptoError(Exception):
    pass
 

