"""
    M2Crypto wrapper for OpenSSL DSA API.

    Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved.

    Portions created by Open Source Applications Foundation (OSAF) are
    Copyright (C) 2004 OSAF. All Rights Reserved.
"""

import sys
import util, BIO, m2

class DSAError(Exception): pass

m2.dsa_init(DSAError)

class DSA:

    """
    This class is a context supporting DSA key and parameter
    values, signing and verifying.
    
    Simple example::
    
        from M2Crypto import EVP, DSA, util
        
        message = 'Kilroy was here!'
        md = EVP.MessageDigest('sha1')
        md.update(message)        
        digest = md.final()
        
        dsa = DSA.gen_params(1024)
        dsa.gen_key()
        r, s = dsa.sign(digest)
        good = dsa.verify(digest, r, s)
        if good:
            print '  ** success **'
        else:
            print '  ** verification failed **'
    """

    m2_dsa_free = m2.dsa_free

    def __init__(self, dsa, _pyfree=0):
        """
        Use one of the factory functions to create an instance.
        """
        assert m2.dsa_type_check(dsa), "'dsa' type error"
        self.dsa = dsa
        self._pyfree = _pyfree
        
    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_dsa_free(self.dsa)

    def __len__(self):
        """
        Return the key length.
    
        @rtype:   int
        @return:  the DSA key length in bits
        """
        assert m2.dsa_type_check(self.dsa), "'dsa' type error"
        return m2.dsa_keylen(self.dsa)

    def __getattr__(self, name):
        """
        Return specified DSA parameters and key values.
    
        @type  name: str
        @param name: name of variable to be returned.  Must be 
                     one of 'p', 'q', 'g', 'pub', 'priv'.
        @rtype:      str
        @return:     value of specified variable (a "byte string")
        """
        if name in ['p', 'q', 'g', 'pub', 'priv']:
            method = getattr(m2, 'dsa_get_%s' % (name,))
            assert m2.dsa_type_check(self.dsa), "'dsa' type error"
            return method(self.dsa)
        else:
            raise AttributeError

    def __setattr__(self, name, value):
        if name in ['p', 'q', 'g']:
            raise DSAError('set (p, q, g) via set_params()')
        elif name in ['pub','priv']:
            raise DSAError('generate (pub, priv) via gen_key()')
        else:
            self.__dict__[name] = value

    def set_params(self, p, q, g):
        """
        Set new parameters.
        
        @warning: This does not change the private key, so it may be
                  unsafe to use this method. It is better to use
                  gen_params function to create a new DSA object.
        """
        m2.dsa_set_p(self.dsa, p)
        m2.dsa_set_q(self.dsa, q)
        m2.dsa_set_g(self.dsa, g)

    def gen_key(self):
        """
        Generate a key pair.
        """
        assert m2.dsa_type_check(self.dsa), "'dsa' type error"
        m2.dsa_gen_key(self.dsa)   

    def save_params(self, filename):
        """
        Save the DSA parameters to a file.
    
        @type  filename: str
        @param filename: Save the DSA parameters to this file.
        @return:         1 (true) if successful
        """
        bio = BIO.openfile(filename, 'wb')
        ret = m2.dsa_write_params_bio(self.dsa, bio._ptr())
        bio.close()
        return ret

    def save_params_bio(self, bio):
        """
        Save DSA parameters to a BIO object.
    
        @type  bio: M2Crypto.BIO object
        @param bio: Save DSA parameters to this object.
        @return:    1 (true) if successful
        """
        return m2.dsa_write_params_bio(self.dsa, bio._ptr())

    def save_key(self, filename, cipher='aes_128_cbc', 
                 callback=util.passphrase_callback):
        """
        Save the DSA key pair to a file.
    
        @type  filename: str
        @param filename: Save the DSA key pair to this file.
        @type  cipher:   str
        @param cipher:   name of symmetric key algorithm and mode
                         to encrypt the private key.
        @return:         1 (true) if successful
        """
        bio = BIO.openfile(filename, 'wb')
        ret = self.save_key_bio(bio, cipher, callback)
        bio.close()
        return ret

    def save_key_bio(self, bio, cipher='aes_128_cbc', 
                     callback=util.passphrase_callback):
        """
        Save DSA key pair to a BIO object.
    
        @type  bio:    M2Crypto.BIO object
        @param bio:    Save DSA parameters to this object.
        @type  cipher: str
        @param cipher: name of symmetric key algorithm and mode
                       to encrypt the private key.
        @return:       1 (true) if successful
        """
        if cipher is None:
            return m2.dsa_write_key_bio_no_cipher(self.dsa, 
                                                 bio._ptr(), callback)
        else:
            ciph = getattr(m2, cipher, None)
            if ciph is None:
                raise DSAError('no such cipher: %s' % cipher)
            else:
                ciph = ciph()
            return m2.dsa_write_key_bio(self.dsa, bio._ptr(), ciph, callback)

    def save_pub_key(self, filename):
        """
        Save the DSA public key (with parameters) to a file.
    
        @type  filename: str
        @param filename: Save DSA public key (with parameters) 
                         to this file.
        @return:         1 (true) if successful
        """
        bio = BIO.openfile(filename, 'wb')
        ret = self.save_pub_key_bio(bio)
        bio.close()
        return ret

    def save_pub_key_bio(self, bio):
        """
        Save DSA public key (with parameters) to a BIO object.
    
        @type  bio: M2Crypto.BIO object
        @param bio: Save DSA public key (with parameters) 
                    to this object.
        @return:  1 (true) if successful
        """
        return m2.dsa_write_pub_key_bio(self.dsa, bio._ptr())

    def sign(self, digest):
        """
        Sign the digest.
    
        @type  digest: str
        @param digest: SHA-1 hash of message (same as output 
                       from MessageDigest, a "byte string")
        @rtype:        tuple
        @return:       DSA signature, a tuple of two values, r and s,
                       both "byte strings".
        """
        assert self.check_key(), 'key is not initialised'
        return m2.dsa_sign(self.dsa, digest)
    
    def verify(self, digest, r, s):
        """
        Verify a newly calculated digest against the signature 
        values r and s.
    
        @type  digest: str
        @param digest: SHA-1 hash of message (same as output 
                       from MessageDigest, a "byte string")
        @type  r:      str
        @param r:      r value of the signature, a "byte string"
        @type  s:      str
        @param s:      s value of the signature, a "byte string"
        @rtype:        int
        @return:       1 (true) if verify succeeded, 0 if failed
        """
        assert self.check_key(), 'key is not initialised'
        return m2.dsa_verify(self.dsa, digest, r, s)

    def sign_asn1(self, digest):
        assert self.check_key(), 'key is not initialised'
        return m2.dsa_sign_asn1(self.dsa, digest)
    
    def verify_asn1(self, digest, blob):
        assert self.check_key(), 'key is not initialised'
        return m2.dsa_verify_asn1(self.dsa, digest, blob)

    def check_key(self):
        """
        Check to be sure the DSA object has a valid private key.
    
        @rtype:   int
        @return:  1 (true) if a valid private key
        """
        assert m2.dsa_type_check(self.dsa), "'dsa' type error"
        return m2.dsa_check_key(self.dsa)
        


class DSA_pub(DSA):

    """
    This class is a DSA context that only supports a public key 
    and verification.  It does NOT support a private key or 
    signing.
    
    """

    def sign(self, *argv):
        raise DSAError('DSA_pub object has no private key')

    sign_asn1 = sign

    def check_key(self):
        return m2.dsa_check_pub_key(self.dsa)
    
    save_key = DSA.save_pub_key

    save_key_bio = DSA.save_pub_key_bio

#---------------------------------------------------------------
# factories and other functions 

def gen_params(bits, callback=util.genparam_callback):
    """
    Factory function that generates DSA parameters and 
    instantiates a DSA object from the output.

    @type  bits: int
    @param bits: The length of the prime to be generated. If 
                 'bits' < 512, it is set to 512.
    @type  callback: function
    @param callback: A Python callback object that will be 
                 invoked during parameter generation; it usual 
                 purpose is to provide visual feedback.
    @rtype:   DSA
    @return:  instance of DSA.
    """
    dsa = m2.dsa_generate_parameters(bits, callback)
    if dsa is None:
        raise DSAError('problem generating DSA parameters')
    return DSA(dsa, 1)

def set_params(p, q, g):
    """
    Factory function that instantiates a DSA object with DSA
    parameters.

    @type  p: str
    @param p: value of p, a "byte string"
    @type  q: str
    @param q: value of q, a "byte string"
    @type  g: str
    @param g: value of g, a "byte string"
    @rtype:   DSA
    @return:  instance of DSA.
    """
    dsa = m2.dsa_new()
    m2.dsa_set_p(dsa, p)
    m2.dsa_set_q(dsa, q)
    m2.dsa_set_g(dsa, g)
    return DSA(dsa, 1)

def load_params(file, callback=util.passphrase_callback):
    """
    Factory function that instantiates a DSA object with DSA 
    parameters from a file.

    @type  file:     str
    @param file:     Names the file (a path) that contains the PEM 
                     representation of the DSA parameters. 
    @type  callback: A Python callable
    @param callback: A Python callback object that will be 
                     invoked if the DSA parameters file is 
                     passphrase-protected.
    @rtype:          DSA
    @return:         instance of DSA.
    """
    bio = BIO.openfile(file)
    ret = load_params_bio(bio, callback)
    bio.close()
    return ret


def load_params_bio(bio, callback=util.passphrase_callback):
    """
    Factory function that instantiates a DSA object with DSA
    parameters from a M2Crypto.BIO object.

    @type  bio:      M2Crypto.BIO object
    @param bio:      Contains the PEM representation of the DSA 
                     parameters. 
    @type  callback: A Python callable
    @param callback: A Python callback object that will be 
                     invoked if the DSA parameters file is 
                     passphrase-protected.
    @rtype:          DSA
    @return:         instance of DSA.
    """
    dsa = m2.dsa_read_params(bio._ptr(), callback)
    if dsa is None:
        raise DSAError('problem loading DSA parameters')
    return DSA(dsa, 1)


def load_key(file, callback=util.passphrase_callback):
    """
    Factory function that instantiates a DSA object from a
    PEM encoded DSA key pair.

    @type  file:     str
    @param file:     Names the file (a path) that contains the PEM 
                     representation of the DSA key pair. 
    @type  callback: A Python callable
    @param callback: A Python callback object that will be 
                     invoked if the DSA key pair is 
                     passphrase-protected.
    @rtype:          DSA
    @return:         instance of DSA.
    """
    bio = BIO.openfile(file)
    ret = load_key_bio(bio, callback)
    bio.close()
    return ret


def load_key_bio(bio, callback=util.passphrase_callback):
    """
    Factory function that instantiates a DSA object from a
    PEM encoded DSA key pair.

    @type  bio:      M2Crypto.BIO object
    @param bio:      Contains the PEM representation of the DSA 
                     key pair. 
    @type  callback: A Python callable
    @param callback: A Python callback object that will be 
                     invoked if the DSA key pair is 
                     passphrase-protected.
    @rtype:          DSA
    @return:         instance of DSA.
    """
    dsa = m2.dsa_read_key(bio._ptr(), callback)
    if not dsa:
        raise DSAError('problem loading DSA key pair')
    return DSA(dsa, 1)


def load_pub_key(file, callback=util.passphrase_callback):
    """
    Factory function that instantiates a DSA_pub object using
    a DSA public key contained in PEM file.  The PEM file 
    must contain the parameters in addition to the public key.

    @type  file:     str
    @param file:     Names the file (a path) that contains the PEM 
                     representation of the DSA public key. 
    @type  callback: A Python callable
    @param callback: A Python callback object that will be 
                     invoked should the DSA public key be 
                     passphrase-protected.
    @rtype:          DSA_pub
    @return:         instance of DSA_pub.
    """
    bio = BIO.openfile(file)
    ret = load_pub_key_bio(bio, callback)
    bio.close()
    return ret


def load_pub_key_bio(bio, callback=util.passphrase_callback):
    """
    Factory function that instantiates a DSA_pub object using
    a DSA public key contained in PEM format.  The PEM 
    must contain the parameters in addition to the public key.

    @type  bio:      M2Crypto.BIO object
    @param bio:      Contains the PEM representation of the DSA 
                     public key (with params). 
    @type  callback: A Python callable
    @param callback: A Python callback object that will be 
                     invoked should the DSA public key be 
                     passphrase-protected.
    @rtype:          DSA_pub
    @return:         instance of DSA_pub.
    """
    dsapub = m2.dsa_read_pub_key(bio._ptr(), callback)
    if not dsapub:
        raise DSAError('problem loading DSA public key')
    return DSA_pub(dsapub, 1)
