"""
M2Crypto threading support, required for multithreaded applications. 

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

# M2Crypto
import m2

def init():
    """
    Initialize threading support.
    """
    m2.threading_init()

def cleanup():
    """
    End and cleanup threading support.
    """
    m2.threading_cleanup()

