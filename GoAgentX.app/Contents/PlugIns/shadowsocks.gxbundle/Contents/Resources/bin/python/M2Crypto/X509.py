"""M2Crypto wrapper for OpenSSL X509 API.

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.
Author: Heikki Toivonen
"""

# M2Crypto
from M2Crypto import ASN1, BIO, Err, EVP, util
import m2

FORMAT_DER = 0
FORMAT_PEM = 1

class X509Error(Exception): pass

m2.x509_init(X509Error)

V_OK = m2.X509_V_OK

def new_extension(name, value, critical=0, _pyfree=1):
    """
    Create new X509_Extension instance.
    """
    if name == 'subjectKeyIdentifier' and \
        value.strip('0123456789abcdefABCDEF:') is not '':
        raise ValueError('value must be precomputed hash')
    lhash = m2.x509v3_lhash()
    ctx = m2.x509v3_set_conf_lhash(lhash)
    x509_ext_ptr = m2.x509v3_ext_conf(lhash, ctx, name, value)
    x509_ext = X509_Extension(x509_ext_ptr, _pyfree)
    x509_ext.set_critical(critical)
    return x509_ext 


class X509_Extension:
    """
    X509 Extension
    """
    
    m2_x509_extension_free = m2.x509_extension_free
    
    def __init__(self, x509_ext_ptr=None, _pyfree=1):
        self.x509_ext = x509_ext_ptr
        self._pyfree = _pyfree

    def __del__(self):
        if getattr(self, '_pyfree', 0) and self.x509_ext:
            self.m2_x509_extension_free(self.x509_ext)

    def _ptr(self):
        return self.x509_ext

    def set_critical(self, critical=1):
        """
        Mark this extension critical or noncritical. By default an
        extension is not critical.

        @type critical:  int
        @param critical: Nonzero sets this extension as critical.
                         Calling this method without arguments will
                         set this extension to critical.
        """
        return m2.x509_extension_set_critical(self.x509_ext, critical)
    
    def get_critical(self):
        """
        Return whether or not this is a critical extension.

        @rtype:   int
        @return:  Nonzero if this is a critical extension.
        """
        return m2.x509_extension_get_critical(self.x509_ext)
    
    def get_name(self):
        """
        Get the extension name, for example 'subjectAltName'.
        """
        return m2.x509_extension_get_name(self.x509_ext)

    def get_value(self, flag=0, indent=0):
        """
        Get the extension value, for example 'DNS:www.example.com'.
        
        @param flag:   Flag to control what and how to print.
        @param indent: How many spaces to print before actual value.
        """
        buf=BIO.MemoryBuffer()
        m2.x509_ext_print(buf.bio_ptr(), self.x509_ext, flag, indent)
        return buf.read_all()    


class X509_Extension_Stack:
    """
    X509 Extension Stack
    
    @warning: Do not modify the underlying OpenSSL stack
    except through this interface, or use any OpenSSL functions that do so
    indirectly. Doing so will get the OpenSSL stack and the internal pystack
    of this class out of sync, leading to python memory leaks, exceptions
    or even python crashes!
    """

    m2_sk_x509_extension_free = m2.sk_x509_extension_free

    def __init__(self, stack=None, _pyfree=0):
        if stack is not None:
            self.stack = stack
            self._pyfree = _pyfree
            num = m2.sk_x509_extension_num(self.stack)
            for i in range(num):
                self.pystack.append(X509_Extension(m2.sk_x509_extension_value(self.stack, i),
                                                   _pyfree=_pyfree))
        else:
            self.stack = m2.sk_x509_extension_new_null()
            self._pyfree = 1
            self.pystack = [] # This must be kept in sync with self.stack
        
    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_sk_x509_extension_free(self.stack)

    def __len__(self):
        assert m2.sk_x509_extension_num(self.stack) == len(self.pystack)
        return len(self.pystack)

    def __getitem__(self, idx):
        return self.pystack[idx]
    
    def __iter__(self):
        return iter(self.pystack)
 
    def _ptr(self):
        return self.stack

    def push(self, x509_ext):
        """
        Push X509_Extension object onto the stack.

        @type x509_ext: M2Crypto.X509.X509_Extension
        @param x509_ext: X509_Extension object to be pushed onto the stack.
        @return: The number of extensions on the stack.
        """
        self.pystack.append(x509_ext)
        ret = m2.sk_x509_extension_push(self.stack, x509_ext._ptr())
        assert ret == len(self.pystack)
        return ret

    def pop(self):
        """
        Pop X509_Extension object from the stack.
        
        @return: X509_Extension popped
        """
        x509_ext_ptr = m2.sk_x509_extension_pop(self.stack)
        if x509_ext_ptr is None:
            assert len(self.pystack) == 0
            return None
        return self.pystack.pop()


class X509_Name_Entry:
    """
    X509 Name Entry
    """

    m2_x509_name_entry_free = m2.x509_name_entry_free

    def __init__(self, x509_name_entry, _pyfree=0):
        self.x509_name_entry = x509_name_entry
        self._pyfree = _pyfree
        
    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_x509_name_entry_free(self.x509_name_entry)

    def _ptr(self):
        return self.x509_name_entry

    def set_object(self, asn1obj):
        return m2.x509_name_entry_set_object(self.x509_name_entry,
                                             asn1obj._ptr())

    def set_data(self, data, type=ASN1.MBSTRING_ASC):
        return m2.x509_name_entry_set_data(self.x509_name_entry,
                                           type, data)

    def get_object(self):
        return ASN1.ASN1_Object(m2.x509_name_entry_get_object(self.x509_name_entry))
        
    def get_data(self):
        return ASN1.ASN1_String(m2.x509_name_entry_get_data(self.x509_name_entry))

    def create_by_txt( self, field, type, entry, len):
        return m2.x509_name_entry_create_by_txt(self.x509_name_entry._ptr(),
                                                field, type, entry, len)
    

class X509_Name:
    """
    X509 Name
    """

    nid = {'C'                      : m2.NID_countryName,
           'SP'                     : m2.NID_stateOrProvinceName,
           'ST'                     : m2.NID_stateOrProvinceName,
           'stateOrProvinceName'    : m2.NID_stateOrProvinceName,
           'L'                      : m2.NID_localityName,
           'localityName'           : m2.NID_localityName,
           'O'                      : m2.NID_organizationName,
           'organizationName'       : m2.NID_organizationName,
           'OU'                     : m2.NID_organizationalUnitName,
           'organizationUnitName'   : m2.NID_organizationalUnitName,
           'CN'                     : m2.NID_commonName,
           'commonName'             : m2.NID_commonName,
           'Email'                  : m2.NID_pkcs9_emailAddress,
           'emailAddress'           : m2.NID_pkcs9_emailAddress,
           'serialNumber'           : m2.NID_serialNumber,
           'SN'                     : m2.NID_surname,
           'surname'                : m2.NID_surname,
           'GN'                     : m2.NID_givenName,
           'givenName'              : m2.NID_givenName
           }

    m2_x509_name_free = m2.x509_name_free

    def __init__(self, x509_name=None, _pyfree=0):
        if x509_name is not None:
            assert m2.x509_name_type_check(x509_name), "'x509_name' type error"
            self.x509_name = x509_name
            self._pyfree = _pyfree
        else:
            self.x509_name = m2.x509_name_new ()
            self._pyfree = 1
            
    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_x509_name_free(self.x509_name)

    def __str__(self):
        assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error" 
        return m2.x509_name_oneline(self.x509_name)

    def __getattr__(self, attr):
        if attr in self.nid:
            assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error" 
            return m2.x509_name_by_nid(self.x509_name, self.nid[attr])

        if attr in self.__dict__:
            return self.__dict__[attr]

        raise AttributeError, (self, attr)

    def __setattr__(self, attr, value):
        if attr in self.nid:
            assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error"
            return m2.x509_name_set_by_nid(self.x509_name, self.nid[attr], value)

        self.__dict__[attr] = value

    def __len__(self):
        return m2.x509_name_entry_count(self.x509_name)
    
    def __getitem__(self, idx):
        if not 0 <= idx < self.entry_count():
            raise IndexError("index out of range")
        return X509_Name_Entry(m2.x509_name_get_entry(self.x509_name, idx))

    def __iter__(self):
        for i in xrange(self.entry_count()):
            yield self[i]

    def _ptr(self):
        #assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error" 
        return self.x509_name

    def add_entry_by_txt(self, field, type, entry, len, loc, set):
        return m2.x509_name_add_entry_by_txt(self.x509_name, field, type,
                                             entry, len, loc, set )

    def entry_count( self ):
        return m2.x509_name_entry_count( self.x509_name )
    
    def get_entries_by_nid(self, nid):
        ret = []
        lastpos = -1

        while True:
            lastpos = m2.x509_name_get_index_by_nid(self.x509_name, nid,
                                                    lastpos)
            if lastpos == -1:
                break
            
            ret.append(self[lastpos])
        
        return ret
    
    def as_text(self, indent=0, flags=m2.XN_FLAG_COMPAT):
        """
        as_text returns the name as a string.
        
        @param indent: Each line in multiline format is indented 
                       by this many spaces.
        @param flags:  Flags that control how the output should be formatted.
        """
        assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error"
        buf=BIO.MemoryBuffer()
        m2.x509_name_print_ex(buf.bio_ptr(), self.x509_name, indent, flags)
        return buf.read_all()

    def as_der(self):
        assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error"
        return m2.x509_name_get_der(self.x509_name)

    def as_hash(self):
        assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error"
        return m2.x509_name_hash(self.x509_name)

class X509:
    """
    X.509 Certificate
    """

    m2_x509_free = m2.x509_free

    def __init__(self, x509=None, _pyfree=0):
        if x509 is not None:
            assert m2.x509_type_check(x509), "'x509' type error"
            self.x509 = x509
            self._pyfree = _pyfree
        else:
            self.x509 = m2.x509_new ()
            self._pyfree = 1
            
    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_x509_free(self.x509)

    def _ptr(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return self.x509

    def as_text(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        buf=BIO.MemoryBuffer()
        m2.x509_print(buf.bio_ptr(), self.x509)
        return buf.read_all()

    def as_der(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.i2d_x509(self.x509)

    def as_pem(self):
        buf=BIO.MemoryBuffer()
        m2.x509_write_pem(buf.bio_ptr(), self.x509)
        return buf.read_all()

    def save_pem(self, filename):
        """
        save_pem
        """
        bio=BIO.openfile(filename, 'wb')
        return m2.x509_write_pem(bio.bio_ptr(), self.x509)

    def save(self, filename, format=FORMAT_PEM):
        """
        Saves X.509 certificate to a file. Default output
        format is PEM.

        @type filename: string
        @param filename: Name of the file the cert will be saved to.
        @type format: int
        @param format: Controls what output format is used to save the cert.
        Either FORMAT_PEM or FORMAT_DER to save in PEM or DER format.
        Raises a ValueError if an unknow format is used.
        """
        bio = BIO.openfile(filename, 'wb')
        if format == FORMAT_PEM:
            return m2.x509_write_pem(bio.bio_ptr(), self.x509)
        elif format == FORMAT_DER:
            return m2.i2d_x509_bio(bio.bio_ptr(), self.x509)
        else:
            raise ValueError("Unknown filetype. Must be either FORMAT_PEM or FORMAT_DER")

    def set_version(self, version):
        """
        Set version.

        @type version:  int
        @param version: Version number.
        @rtype:         int
        @return:        Returns 0 on failure.
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_version(self.x509, version)

    def set_not_before(self, asn1_utctime):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_not_before(self.x509, asn1_utctime._ptr())

    def set_not_after(self, asn1_utctime):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_not_after(self.x509, asn1_utctime._ptr())

    def set_subject_name(self, name):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_subject_name(self.x509, name.x509_name)

    def set_issuer_name(self, name):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_issuer_name(self.x509, name.x509_name)

    def get_version(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_get_version(self.x509)

    def get_serial_number(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        asn1_integer = m2.x509_get_serial_number(self.x509)
        return m2.asn1_integer_get(asn1_integer)

    def set_serial_number(self, serial):
        """
        Set serial number.

        @type serial:   int
        @param serial:  Serial number.
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        # This "magically" changes serial since asn1_integer
        # is C pointer to x509's internal serial number.
        asn1_integer = m2.x509_get_serial_number(self.x509)
        return m2.asn1_integer_set(asn1_integer, serial)
        # XXX Or should I do this?
        #asn1_integer = m2.asn1_integer_new()
        #m2.asn1_integer_set(asn1_integer, serial)
        #return m2.x509_set_serial_number(self.x509, asn1_integer)

    def get_not_before(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return ASN1.ASN1_UTCTIME(m2.x509_get_not_before(self.x509))

    def get_not_after(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return ASN1.ASN1_UTCTIME(m2.x509_get_not_after(self.x509))

    def get_pubkey(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return EVP.PKey(m2.x509_get_pubkey(self.x509), _pyfree=1)

    def set_pubkey(self, pkey):
        """
        Set the public key for the certificate

        @type pkey:  EVP_PKEY
        @param pkey: Public key
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_pubkey(self.x509, pkey.pkey)

    def get_issuer(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return X509_Name(m2.x509_get_issuer_name(self.x509))

    def set_issuer(self, name):
        """
        Set issuer name.

        @type name:     X509_Name
        @param name:    subjectName field.
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_issuer_name(self.x509, name.x509_name)

    def get_subject(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return X509_Name(m2.x509_get_subject_name(self.x509))

    def set_subject(self, name):
        """
        Set subject name.

        @type name:     X509_Name
        @param name:    subjectName field.
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_subject_name(self.x509, name.x509_name)

    def add_ext(self, ext):
        """
        Add X509 extension to this certificate.

        @type ext:     X509_Extension
        @param ext:    Extension
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_add_ext(self.x509, ext.x509_ext, -1)

    def get_ext(self, name):
        """
        Get X509 extension by name.

        @type name:    Name of the extension
        @param name:   str
        @return:       X509_Extension
        """
        # Optimizations to reduce attribute accesses
        m2x509_get_ext = m2.x509_get_ext
        m2x509_extension_get_name = m2.x509_extension_get_name
        x509 = self.x509
        
        for i in range(m2.x509_get_ext_count(x509)):
            extPtr = m2x509_get_ext(x509, i)
            if m2x509_extension_get_name(extPtr) == name:
                return X509_Extension(extPtr, _pyfree=0)

        raise LookupError

    def get_ext_at(self, index):
        """
        Get X509 extension by index.

        @type index:    Name of the extension
        @param index:   int
        @return:        X509_Extension
        """
        if index < 0 or index >= self.get_ext_count():
            raise IndexError
        
        return X509_Extension(m2.x509_get_ext(self.x509, index),
                              _pyfree=0)

    def get_ext_count(self):
        """
        Get X509 extension count.
        """
        return m2.x509_get_ext_count(self.x509)        

    def sign(self, pkey, md):
        """
        Sign the certificate.

        @type pkey:  EVP_PKEY
        @param pkey: Public key
        @type md:    str
        @param md:   Message digest algorithm to use for signing,
                     for example 'sha1'.
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        mda = getattr(m2, md, None)
        if mda is None:
            raise ValueError, ('unknown message digest', md)
        return m2.x509_sign(self.x509, pkey.pkey, mda())

    def verify(self, pkey=None):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        if pkey:
            return m2.x509_verify(self.x509, pkey.pkey)
        else:
            return m2.x509_verify(self.x509, self.get_pubkey().pkey)
            
    def check_ca(self):
        """
        Check if the certificate is a Certificate Authority (CA) certificate.
        
        @return: 0 if the certificate is not CA, nonzero otherwise.
        
        @requires: OpenSSL 0.9.8 or newer 
        """
        return m2.x509_check_ca(self.x509)
        
    def check_purpose(self, id, ca):
        """
        Check if the certificate's purpose matches the asked purpose.
        
        @param id: Purpose id. See X509_PURPOSE_* constants.
        @param ca: 1 if the certificate should be CA, 0 otherwise.
        @return: 0 if the certificate purpose does not match, nonzero otherwise.
        """
        return m2.x509_check_purpose(self.x509, id, ca)

    def get_fingerprint(self, md='md5'):
        """
        Get the fingerprint of the certificate.
        
        @param md: Message digest algorithm to use.
        @return:   String containing the fingerprint in hex format.
        """
        der = self.as_der()
        md = EVP.MessageDigest(md)
        md.update(der)
        digest = md.final()
        return hex(util.octx_to_num(digest))[2:-1].upper()

def load_cert(file, format=FORMAT_PEM):
    """
    Load certificate from file.

    @type file: string
    @param file: Name of file containing certificate in either DER or PEM format.
    @type format: int, either FORMAT_PEM or FORMAT_DER
    @param format: Describes the format of the file to be loaded, either PEM or DER.

    @rtype: M2Crypto.X509.X509
    @return: M2Crypto.X509.X509 object.
    """
    bio = BIO.openfile(file)
    if format == FORMAT_PEM:
        return load_cert_bio(bio)
    elif format == FORMAT_DER:
        cptr = m2.d2i_x509(bio._ptr())
        if cptr is None:
            raise X509Error(Err.get_error())
        return X509(cptr, _pyfree=1)
    else:
        raise ValueError("Unknown format. Must be either FORMAT_DER or FORMAT_PEM")

def load_cert_bio(bio, format=FORMAT_PEM):
    """
    Load certificate from a bio.

    @type bio: M2Crypto.BIO.BIO
    @param bio: BIO pointing at a certificate in either DER or PEM format.
    @type format: int, either FORMAT_PEM or FORMAT_DER
    @param format: Describes the format of the cert to be loaded, either PEM or DER.

    @rtype: M2Crypto.X509.X509
    @return: M2Crypto.X509.X509 object.
    """
    if format == FORMAT_PEM:
        cptr = m2.x509_read_pem(bio._ptr())
    elif format == FORMAT_DER:
        cptr = m2.d2i_x509(bio._ptr())
    else:
        raise ValueError("Unknown format. Must be either FORMAT_DER or FORMAT_PEM")
    if cptr is None:
        raise X509Error(Err.get_error())
    return X509(cptr, _pyfree=1)

def load_cert_string(string, format=FORMAT_PEM):
    """
    Load certificate from a string.

    @type string: string
    @param string: String containing a certificate in either DER or PEM format.
    @type format: int, either FORMAT_PEM or FORMAT_DER
    @param format: Describes the format of the cert to be loaded, either PEM or DER.

    @rtype: M2Crypto.X509.X509
    @return: M2Crypto.X509.X509 object.
    """
    bio = BIO.MemoryBuffer(string)
    return load_cert_bio(bio, format)

def load_cert_der_string(string):
    """
    Load certificate from a string.

    @type string: string
    @param string: String containing a certificate in DER format.

    @rtype: M2Crypto.X509.X509
    @return: M2Crypto.X509.X509 object.
    """
    bio = BIO.MemoryBuffer(string)
    cptr = m2.d2i_x509(bio._ptr())
    if cptr is None:
        raise X509Error(Err.get_error())
    return X509(cptr, _pyfree=1)

class X509_Store_Context:
    """
    X509 Store Context
    """

    m2_x509_store_ctx_free = m2.x509_store_ctx_free

    def __init__(self, x509_store_ctx, _pyfree=0):
        self.ctx = x509_store_ctx
        self._pyfree = _pyfree
        
    def __del__(self):
        if self._pyfree:
            self.m2_x509_store_ctx_free(self.ctx)
            
    def _ptr(self):
        return self.ctx
            
    def get_current_cert(self):
        """
        Get current X.509 certificate.
        
        @warning: The returned certificate is NOT refcounted, so you can not
        rely on it being valid once the store context goes away or is modified.
        """
        return X509(m2.x509_store_ctx_get_current_cert(self.ctx), _pyfree=0)

    def get_error(self):
        """
        Get error code.
        """
        return m2.x509_store_ctx_get_error(self.ctx)
        
    def get_error_depth(self):
        """
        Get error depth.
        """
        return m2.x509_store_ctx_get_error_depth(self.ctx)
    
    def get1_chain(self):
        """
        Get certificate chain.
        
        @return: Reference counted (i.e. safe to use even after the store
                 context goes away) stack of certificates in the chain.
        @rtype:  X509_Stack
        """
        return X509_Stack(m2.x509_store_ctx_get1_chain(self.ctx), 1, 1)
        

class X509_Store:
    """
    X509 Store
    """

    m2_x509_store_free = m2.x509_store_free

    def __init__(self, store=None, _pyfree=0):
        if store is not None:
            self.store = store
            self._pyfree = _pyfree
        else:
            self.store = m2.x509_store_new()
            self._pyfree = 1
            
    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_x509_store_free(self.store)

    def _ptr(self):
        return self.store

    def load_info(self, file):
        ret = m2.x509_store_load_locations(self.store, file) 
        if ret < 1:
            raise X509Error(Err.get_error())
        return ret

    load_locations = load_info
                 
    def add_x509(self, x509):
        assert isinstance(x509, X509)
        return m2.x509_store_add_cert(self.store, x509._ptr())
        
    add_cert = add_x509


class X509_Stack:
    """
    X509 Stack

    @warning: Do not modify the underlying OpenSSL stack
    except through this interface, or use any OpenSSL functions that do so
    indirectly. Doing so will get the OpenSSL stack and the internal pystack
    of this class out of sync, leading to python memory leaks, exceptions
    or even python crashes!
    """

    m2_sk_x509_free = m2.sk_x509_free

    def __init__(self, stack=None, _pyfree=0, _pyfree_x509=0):
        if stack is not None:
            self.stack = stack
            self._pyfree = _pyfree
            self.pystack = [] # This must be kept in sync with self.stack
            num = m2.sk_x509_num(self.stack)
            for i in range(num):
                self.pystack.append(X509(m2.sk_x509_value(self.stack, i),
                                         _pyfree=_pyfree_x509))
        else:
            self.stack = m2.sk_x509_new_null()
            self._pyfree = 1
            self.pystack = [] # This must be kept in sync with self.stack
        
    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_sk_x509_free(self.stack)
            
    def __len__(self):
        assert m2.sk_x509_num(self.stack) == len(self.pystack)
        return len(self.pystack)

    def __getitem__(self, idx):
        return self.pystack[idx]
    
    def __iter__(self):
        return iter(self.pystack)

    def _ptr(self):
        return self.stack

    def push(self, x509):
        """
        push an X509 certificate onto the stack.
        
        @param x509: X509 object.
        @return: The number of X509 objects currently on the stack.
        """
        assert isinstance(x509, X509)
        self.pystack.append(x509)
        ret = m2.sk_x509_push(self.stack, x509._ptr())
        assert ret == len(self.pystack)
        return ret

    def pop(self):
        """
        pop a certificate from the stack.
        
        @return: X509 object that was popped, or None if there is nothing
        to pop. 
        """
        x509_ptr = m2.sk_x509_pop(self.stack)
        if x509_ptr is None:
            assert len(self.pystack) == 0
            return None
        return self.pystack.pop()

    def as_der(self):
        """
        Return the stack as a DER encoded string
        """
        return m2.get_der_encoding_stack(self.stack)     


def new_stack_from_der(der_string):
    """
    Create a new X509_Stack from DER string.
    
    @return: X509_Stack
    """
    stack_ptr = m2.make_stack_from_der_sequence(der_string)
    if stack_ptr is None:
        raise X509Error(Err.get_error())
    return X509_Stack(stack_ptr, 1, 1)


class Request:
    """
    X509 Certificate Request.
    """

    m2_x509_req_free = m2.x509_req_free

    def __init__(self, req=None, _pyfree=0):
        if req is not None:
            self.req = req
            self._pyfree = _pyfree
        else:
            self.req = m2.x509_req_new()
            self._pyfree = 1
            
    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_x509_req_free(self.req)
            
    def as_text(self):
        buf=BIO.MemoryBuffer()
        m2.x509_req_print(buf.bio_ptr(), self.req)
        return buf.read_all()

    def as_pem(self):
        buf=BIO.MemoryBuffer()
        m2.x509_req_write_pem(buf.bio_ptr(), self.req)
        return buf.read_all()

    def as_der(self):
        buf = BIO.MemoryBuffer()
        m2.i2d_x509_req_bio(buf.bio_ptr(), self.req)
        return buf.read_all()

    def save_pem(self, filename):
        bio=BIO.openfile(filename, 'wb')
        return m2.x509_req_write_pem(bio.bio_ptr(), self.req)
    
    def save(self, filename, format=FORMAT_PEM):
        """
        Saves X.509 certificate request to a file. Default output
        format is PEM.

        @type filename: string
        @param filename: Name of the file the request will be saved to.
        @type format: int
        @param format: Controls what output format is used to save the request.
        Either FORMAT_PEM or FORMAT_DER to save in PEM or DER format.
        Raises ValueError if an unknown format is used.
        """
        bio = BIO.openfile(filename, 'wb')
        if format == FORMAT_PEM:
            return m2.x509_req_write_pem(bio.bio_ptr(), self.req)
        elif format == FORMAT_DER:
            return m2.i2d_x509_req_bio(bio.bio_ptr(), self.req)
        else:
            raise ValueError("Unknown filetype. Must be either FORMAT_DER or FORMAT_PEM")

    def get_pubkey(self):
        """
        Get the public key for the request.

        @rtype:      EVP_PKEY
        @return:     Public key from the request.
        """
        return EVP.PKey(m2.x509_req_get_pubkey(self.req), _pyfree=1)

    def set_pubkey(self, pkey):
        """
        Set the public key for the request.

        @type pkey:  EVP_PKEY
        @param pkey: Public key

        @rtype:      int
        @return:     Return 1 for success and 0 for failure.
        """
        return m2.x509_req_set_pubkey( self.req, pkey.pkey )

    def get_version(self):
        """
        Get version.

        @rtype:         int
        @return:        Returns version.
        """
        return m2.x509_req_get_version(self.req)

    def set_version(self, version):
        """
        Set version.

        @type version:  int
        @param version: Version number.
        @rtype:         int
        @return:        Returns 0 on failure.
        """
        return m2.x509_req_set_version( self.req, version )

    def get_subject(self):
        return X509_Name(m2.x509_req_get_subject_name( self.req ))

    def set_subject_name(self, name):
        """
        Set subject name.

        @type name:     X509_Name
        @param name:    subjectName field.
        """
        return m2.x509_req_set_subject_name( self.req, name.x509_name )

    set_subject = set_subject_name

    def add_extensions(self, ext_stack):
        """
        Add X509 extensions to this request.

        @type ext_stack:  X509_Extension_Stack
        @param ext_stack: Stack of extensions to add.
        """
        return m2.x509_req_add_extensions(self.req, ext_stack._ptr())

    def verify(self, pkey):
        return m2.x509_req_verify(self.req, pkey.pkey)

    def sign(self, pkey, md):
        mda = getattr(m2, md, None)
        if mda is None:
            raise ValueError, ('unknown message digest', md)
        return m2.x509_req_sign(self.req, pkey.pkey, mda())


def load_request(file, format=FORMAT_PEM):
    """
    Load certificate request from file.

    @type file: string
    @param file: Name of file containing certificate request in either PEM or DER format.
    @type format: int, either FORMAT_PEM or FORMAT_DER
    @param format: Describes the format of the file to be loaded, either PEM or DER.

    @rtype: M2Crypto.X509.Request
    @return: M2Crypto.X509.Request object.
    """
    f=BIO.openfile(file)
    if format == FORMAT_PEM:
        cptr=m2.x509_req_read_pem(f.bio_ptr())
    elif format == FORMAT_DER:
        cptr = m2.d2i_x509_req(f.bio_ptr())
    else:
        raise ValueError("Unknown filetype. Must be either FORMAT_PEM or FORMAT_DER")
    f.close()
    if cptr is None:
        raise X509Error(Err.get_error())
    return Request(cptr, 1)

def load_request_bio(bio, format=FORMAT_PEM):
    """
    Load certificate request from a bio.

    @type bio: M2Crypto.BIO.BIO
    @param bio: BIO pointing at a certificate request in either DER or PEM format.
    @type format: int, either FORMAT_PEM or FORMAT_DER
    @param format: Describes the format of the request to be loaded, either PEM or DER.

    @rtype: M2Crypto.X509.Request
    @return: M2Crypto.X509.Request object.
    """
    if format == FORMAT_PEM:
        cptr = m2.x509_req_read_pem(bio._ptr())
    elif format == FORMAT_DER:
        cptr = m2.d2i_x509_req(bio._ptr())
    else:
        raise ValueError("Unknown format. Must be either FORMAT_DER or FORMAT_PEM")
    if cptr is None:
        raise X509Error(Err.get_error())
    return Request(cptr, _pyfree=1)

def load_request_string(string, format=FORMAT_PEM):
    """
    Load certificate request from a string.

    @type string: string
    @param string: String containing a certificate request in either DER or PEM format.
    @type format: int, either FORMAT_PEM or FORMAT_DER
    @param format: Describes the format of the request to be loaded, either PEM or DER.

    @rtype: M2Crypto.X509.Request
    @return: M2Crypto.X509.Request object.
    """
    bio = BIO.MemoryBuffer(string)
    return load_request_bio(bio, format)

def load_request_der_string(string):
    """
    Load certificate request from a string.

    @type string: string
    @param string: String containing a certificate request in DER format.

    @rtype: M2Crypto.X509.Request
    @return: M2Crypto.X509.Request object.
    """
    bio = BIO.MemoryBuffer(string)
    return load_request_bio(bio, FORMAT_DER)


class CRL:
    """
    X509 Certificate Revocation List
    """

    m2_x509_crl_free = m2.x509_crl_free

    def __init__(self, crl=None, _pyfree=0):
        if crl is not None:
            self.crl = crl
            self._pyfree = _pyfree
        else:
            self.crl = m2.x509_crl_new()
            self._pyfree = 1
            
    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_x509_crl_free(self.crl)

    def as_text(self):
        """
        Return CRL in PEM format in a string.

        @rtype: string
        @return: String containing the CRL in PEM format.
        """
        buf=BIO.MemoryBuffer()
        m2.x509_crl_print(buf.bio_ptr(), self.crl)
        return buf.read_all()


def load_crl(file):
    """
    Load CRL from file.

    @type file: string
    @param file: Name of file containing CRL in PEM format.

    @rtype: M2Crypto.X509.CRL
    @return: M2Crypto.X509.CRL object.
    """
    f=BIO.openfile(file)
    cptr=m2.x509_crl_read_pem(f.bio_ptr())
    f.close()
    if cptr is None:
        raise X509Error(Err.get_error())
    return CRL(cptr, 1)


