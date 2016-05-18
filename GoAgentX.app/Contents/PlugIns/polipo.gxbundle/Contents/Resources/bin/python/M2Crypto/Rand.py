"""M2Crypto wrapper for OpenSSL PRNG. Requires OpenSSL 0.9.5 and above.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

__all__ = ['rand_seed', 'rand_add', 'load_file', 'save_file', 'rand_bytes',
           'rand_pseudo_bytes']

import m2

rand_seed           = m2.rand_seed
rand_add            = m2.rand_add
load_file           = m2.rand_load_file
save_file           = m2.rand_save_file
rand_bytes          = m2.rand_bytes
rand_pseudo_bytes   = m2.rand_pseudo_bytes


