[![Build Status](https://travis-ci.org/jonasschnelli/chacha20poly1305.svg?branch=master)](https://travis-ci.org/jonasschnelli/chacha20poly1305) 

chacha20/poly1305/chacha20poly1305 openssh aead
=====

Simple C module for chacha20, poly1305 and chacha20poly1305@openssh AEAD

Features:
* Simple, pure C code without any dependencies.

Performance
-----------

-

Build steps
-----------

Object code:

    $ gcc -O3 -c -fPIC poly1305.c chacha.c chachapoly_aead.c

Tests:

    $ gcc -O3 poly1305.c chacha.c chachapoly_aead.c tests.c -o test

Benchmark:

    $ gcc -O3 poly1305.c chacha.c chachapoly_aead.c bench.c -o bench

Shared libraries:
    
    $ gcc -Wall -g chacha.o -shared -o libchacha.so
    $ gcc -Wall -g poly1305.o -shared -o libpoly1305.so
    $ gcc -Wall -g chacha.o poly1305.o  chachapoly_aead.o -shared -o libchachapoly_aead.so

Add build directory to LD_LIBRARY_PATH:
    
    $ LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<path_to_build_directory>


pychachapoly
------------

*pychachapoly* is a Python 2/3 wrapper that gives access to the shared libraries compiled in the steps above and is used to perform unit tests of the chacha20/poly1305/chacha20poly1305 C library functions.

To run the unit tests, add the project (build) directory to your shell LD_LIBRARY_PATH, and then execute:
    
    $ python unittests/test_pychachapoly.py

*pychachapoly* can also be used as a Python module that provides the OpenSSH implementation of chacha20poly1305 authenticated encryption and additional data (AEAD):

```python
    import pychachapoly as pccp
    import binascii
    
    # crypt material must be bytes format
    plaintext = b"Hello Bitcoin!"
    
    # provide two keys, 32 bytes each, concatenated
    keystr = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\
             '0000000000000000000000000000000000000000000000000000000000000000'
    keys = binascii.unhexlify(keystr)
    
    # initialize aead object
    aead_obj = pccp.chacha20poly1305_init(keys)
    
    # encrypt
    ciphertext = pccp.chacha20poly1305_crypt(aead_obj, inbuf=plaintext, nonce=100, alen=4, is_encrypt=1)
    
    # decrypt
    res = pccp.chacha20poly1305_crypt(aead_obj, inbuf=ciphertext, nonce=100, alen=4, is_encrypt=0)
    
    >>> print(res)
    b"Hello Bitcoin!"
```

The encrypted data length is extracted from ciphertext in a separate operation, using the same aead object initialized above:
```
    >>> len_out = pccp.chacha20poly1305_get_length(aead_obj, ciphertext, nonce=100, alen=4)
```

*pychachapoly* wrapper code is beta release. Code comments and unittest examples may be useful.
