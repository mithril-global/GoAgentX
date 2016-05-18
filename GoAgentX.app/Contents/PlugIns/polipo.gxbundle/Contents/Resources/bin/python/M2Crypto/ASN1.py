"""
M2Crypto wrapper for OpenSSL ASN1 API.

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2005 OSAF. All Rights Reserved.
"""

import time, datetime

import BIO
import m2

MBSTRING_FLAG = 0x1000
MBSTRING_ASC  = MBSTRING_FLAG | 1
MBSTRING_BMP  = MBSTRING_FLAG | 2


class ASN1_Integer:

    m2_asn1_integer_free = m2.asn1_integer_free

    def __init__(self, asn1int, _pyfree=0):
        self.asn1int = asn1int
        self._pyfree = _pyfree
        
    def __cmp__(self, other):
        return m2.asn1_integer_cmp(self.asn1int, other.asn1int)

    def __del__(self):
        if self._pyfree:
            self.m2_asn1_integer_free(self.asn1int)


class ASN1_String:
        
    m2_asn1_string_free = m2.asn1_string_free
    
    def __init__(self, asn1str, _pyfree=0):
        self.asn1str = asn1str
        self._pyfree = _pyfree

    def __str__(self):
        buf = BIO.MemoryBuffer()
        m2.asn1_string_print( buf.bio_ptr(), self.asn1str )
        return buf.read_all()

    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_asn1_string_free(self.asn1str)
                                                                                                        
    def _ptr(self):
        return self.asn1str
    
    def as_text(self, flags=0):
        buf = BIO.MemoryBuffer()
        m2.asn1_string_print_ex( buf.bio_ptr(), self.asn1str, flags)
        return buf.read_all()


class ASN1_Object:
    
    m2_asn1_object_free = m2.asn1_object_free

    def __init__(self, asn1obj, _pyfree=0):
        self.asn1obj = asn1obj
        self._pyfree = _pyfree
        
    def __del__(self):
        if self._pyfree:
            self.m2_asn1_object_free(self.asn1obj)

    def _ptr(self):
        return self.asn1obj

class _UTC(datetime.tzinfo):
    def tzname(self, dt):
        return "UTC"
    
    def dst(self, dt):
        return datetime.timedelta(0)
    
    def utcoffset(self, dt):
        return datetime.timedelta(0)

    def __repr__(self):
        return "<Timezone: %s>" % self.tzname(None)
UTC = _UTC()


class LocalTimezone(datetime.tzinfo):
    """ Localtimezone from datetime manual """
    def __init__(self):
        self._stdoffset = datetime.timedelta(seconds = -time.timezone)
        if time.daylight:
            self._dstoffset = datetime.timedelta(seconds = -time.altzone)
        else:
            self._dstoffset = self._stdoffset
        self._dstdiff = self._dstoffset - self._stdoffset


    def utcoffset(self, dt):
        if self._isdst(dt):
            return self._dstoffset
        else:
            return self._stdoffset

    def dst(self, dt):
        if self._isdst(dt):
            return self._dstdiff
        else:
            return datetime.timedelta(0)

    def tzname(self, dt):
        return time.tzname[self._isdst(dt)]

    def _isdst(self, dt):
        tt = (dt.year, dt.month, dt.day,
              dt.hour, dt.minute, dt.second,
              dt.weekday(), 0, -1)
        stamp = time.mktime(tt)
        tt = time.localtime(stamp)
        return tt.tm_isdst > 0


class ASN1_UTCTIME:
    _ssl_months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                   "Sep", "Oct", "Nov", "Dec"]
    m2_asn1_utctime_free = m2.asn1_utctime_free

    def __init__(self, asn1_utctime=None, _pyfree=0):
        if asn1_utctime is not None:
            assert m2.asn1_utctime_type_check(asn1_utctime), "'asn1_utctime' type error'"
            self.asn1_utctime = asn1_utctime
            self._pyfree = _pyfree
        else:
            self.asn1_utctime = m2.asn1_utctime_new ()
            self._pyfree = 1
            
    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_asn1_utctime_free(self.asn1_utctime)
            
    def __str__(self):
        assert m2.asn1_utctime_type_check(self.asn1_utctime), "'asn1_utctime' type error'"
        buf = BIO.MemoryBuffer()
        m2.asn1_utctime_print( buf.bio_ptr(), self.asn1_utctime )
        return buf.read_all()

    def _ptr(self):
        assert m2.asn1_utctime_type_check(self.asn1_utctime), "'asn1_utctime' type error'"
        return self.asn1_utctime

    def set_string (self, string):
        """
        Set time from UTC string.
        """
        assert m2.asn1_utctime_type_check(self.asn1_utctime), "'asn1_utctime' type error'"
        return m2.asn1_utctime_set_string( self.asn1_utctime, string )

    def set_time (self, time):
        """
        Set time from seconds since epoch (long).
        """
        assert m2.asn1_utctime_type_check(self.asn1_utctime), "'asn1_utctime' type error'"
        return m2.asn1_utctime_set( self.asn1_utctime, time )

    def get_datetime(self):
        date = str(self)

        timezone = None
        if ' ' not in date:
            raise ValueError("Invalid date: %s" % date)
        month, rest = date.split(' ', 1)
        if month not in self._ssl_months:
            raise ValueError("Invalid date %s: Invalid month: %s" % (date, m))
        if rest.endswith(' GMT'):
            timezone = UTC
            rest = rest[:-4]
        tm = list(time.strptime(rest, "%d %H:%M:%S %Y"))[:6]
        tm[1] = self._ssl_months.index(month) + 1
        tm.append(0)
        tm.append(timezone)
        return datetime.datetime(*tm)

    def set_datetime(self, date):
        local = LocalTimezone()
        if date.tzinfo is None:
            date = date.replace(tzinfo=local)
        date = date.astimezone(local)
        return self.set_time(int(time.mktime(date.timetuple())))
