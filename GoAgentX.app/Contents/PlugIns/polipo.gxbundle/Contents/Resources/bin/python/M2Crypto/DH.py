"""M2Crypto wrapper for OpenSSL DH API.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

from util import genparam_callback
import BIO, Err, m2

class DHError(Exception): pass

m2.dh_init(DHError)

class DH:

    """
    Object interface to the Diffie-Hellman key exchange
    protocol.
    """

    m2_dh_free = m2.dh_free

    def __init__(self, dh, _pyfree=0):
        assert m2.dh_type_check(dh)
        self.dh = dh
        self._pyfree = _pyfree
        
    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_dh_free(self.dh)

    def __len__(self):
        assert m2.dh_type_check(self.dh), "'dh' type error"
        return m2.dh_size(self.dh)

    def __getattr__(self, name):
        if name in ('p', 'g', 'pub', 'priv'):
            method = getattr(m2, 'dh_get_%s' % (name,))
            assert m2.dh_type_check(self.dh), "'dh' type error"
            return method(self.dh)
        else:
            raise AttributeError

    def __setattr__(self, name, value):
        if name in ('p', 'g'):
            raise DHError, 'set (p, g) via set_params()'
        elif name in ('pub','priv'):
            raise DHError, 'generate (pub, priv) via gen_key()'
        else:
            self.__dict__[name] = value

    def _ptr(self):
        return self.dh

    def check_params(self):
        assert m2.dh_type_check(self.dh), "'dh' type error"
        return m2.dh_check(self.dh)
        
    def gen_key(self):
        assert m2.dh_type_check(self.dh), "'dh' type error"
        m2.dh_generate_key(self.dh)   

    def compute_key(self, pubkey):
        assert m2.dh_type_check(self.dh), "'dh' type error"
        return m2.dh_compute_key(self.dh, pubkey)

    def print_params(self, bio):
        assert m2.dh_type_check(self.dh), "'dh' type error"
        return m2.dhparams_print(bio._ptr(), self.dh)


def gen_params(plen, g, callback=genparam_callback):
    return DH(m2.dh_generate_parameters(plen, g, callback), 1)


def load_params(file):
    bio = BIO.openfile(file)
    return load_params_bio(bio)


def load_params_bio(bio):
    return DH(m2.dh_read_parameters(bio._ptr()), 1)


def set_params(p, g):
    dh = m2.dh_new()
    m2.dh_set_p(dh, p)
    m2.dh_set_g(dh, g)
    return DH(dh, 1)


#def free_params(cptr):
#    m2.dh_free(cptr)


DH_GENERATOR_2 = m2.DH_GENERATOR_2
DH_GENERATOR_5 = m2.DH_GENERATOR_5

