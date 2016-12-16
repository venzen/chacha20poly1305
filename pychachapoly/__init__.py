#!/usr/bin/env python3
""" 
pychachapoly is a Python wrapper for the chacha20poly1305@openssh.com
C library implementation written by Jonas Schnelli and available at:
    
https://github.com/jonasschnelli/chacha20poly1305

This wrapper copyright (c) 2016, Venzen Khaosan
Distributed under the MIT software license, see the accompanying
file COPYING or http://www.opensource.org/licenses/mit-license.php
"""

import sys
import ctypes
import binascii
import inspect      # beta only: return the name of the calling function


# load libraries from LD_LIBRARY_PATH
# give the user some pointers if they didn't README.md
try:
    lastlib = "libchacha.so"
    libcha = ctypes.CDLL(lastlib)
    print('loaded %s' % libcha._name)
    
    lastlib = "libpoly1305.so"
    libpoly = ctypes.CDLL(lastlib)
    print('loaded %s' % libpoly._name)
    
    lastlib = "libchachapoly_aead.so"
    libaead = ctypes.CDLL(lastlib)
    print('loaded %s' % libaead._name)
    
except Exception as e:
    print('exception loading %s: %s' % (lastlib, e))
    import os
    libpath = os.path.abspath(os.path.dirname(__file__))
    if libpath not in os.environ['LD_LIBRARY_PATH']:
        print('\nadd %s to LD_LIBRARY_PATH:\n' % libpath)
        sys.exit(1)
    else:
        print('\ncheck that %s is in %s\n' % (lastlib, libpath))
        sys.exit(1)


# constants from poly.h
POLY1305_KEYLEN = 32
POLY1305_TAGLEN = 16
# constants from chacha.h
CHACHA_MINKEYLEN = 16
CHACHA_NONCELEN = 8
CHACHA_CTRLEN = 8
CHACHA_STATELEN = CHACHA_NONCELEN + CHACHA_CTRLEN
CHACHA_BLOCKLEN = 64


# Utility functions
def __check_exit(code):
    """ print C function exit code """
    if code == 0:
        print('(exit code 0)')
    else:
        print('(%s() exit code = %s)' % (inspect.stack()[1][3], code))

def hexbytes_to_intarray(bytestr):
    """ unpack hex byte string (e.g. '\ x00\ x00\ x00\ x...') to integers 
        return a Python list of integers
    """
    intarray = []
    if sys.version_info.major == 3:
        for b in bytestr:
            intarray.append(b)
    else:
        for b in bytestr:
            h = '0x%s' % b.encode('hex')
            i = int(h, 0)
            intarray.append(i)
    return intarray

def intarray_to_carray(intarr, carr):
    """ copy an array of integers into a prepared C array 
        return the C array
    """
    i = 0
    for x in intarr:
        carr[i] = x
        i += 1
    return carr

def array_to_hexstr(arr):
    """ pack a Python list or C array of int bytes into a hex string
        return a hex string
    """
    #TODO this could be generalized to str instead of 'hex string'
    # However, despite highlevel Python interface, accepting bytes 
    # input and return values is prefered for crypt functions
    hexstring = ''
    for x in arr:
        hbyte = hex(x)[2:]
        if len(hbyte) & 1:
            hbyte = '0%s' % hbyte
        hexstring = '%s%s' % (hexstring, hbyte)
    return hexstring

def intarray_to_bytestr(arr):
    """ pack a Python list or C array of int bytes into a byte string
        return a byte string
    """
    bytestring = ''
    if sys.version_info.major == 3:
        return bytes([x for x in arr])
    else:
        for x in arr:
            hbyte = chr(x)
            bytestring = '%s%s' % (bytestring, hbyte)
    return bytestring

##
# Start of C library mappings

class ChaChaCTX(ctypes.Structure):
    """
    Class object mapping for C struct chacha_ctx.
    'input' attribute stores key material in a 16 byte C type array.
    """
    
    _fields_ = [
                ('input', ctypes.c_uint32 * CHACHA_MINKEYLEN)
                ]

      
class AEAD(ctypes.Structure):
    """
    Class object mapping for C struct chachapolyaead_ctx.
    
    Returned by chacha20poly1305_init() and contains two instances
    of class ChaChaCTX - assigned to attributes 'main' and 'header', 
    repsectively.
    
    K_1 (stored in main.input) is used to crypt payload data.
    K_2 (stored in header.input) crypts payload size.
    """
    
    #_pack_ = 1
    _fields_ = [
                ('main', ChaChaCTX),
                ('header', ChaChaCTX)
                ]

    
#void chacha_ivsetup(chacha_ctx *x, const u8 *iv, const u8 *counter)
#
def chacha_ivsetup(chachactx_obj, nonce=0, counter=None):
    """ _ivsetup() can only be called after an initial call to
        _keysetup() has instantiated the ctx obj with a key
    """
    if isinstance(chachactx_obj, ChaChaCTX):
        chacha_ctx = chachactx_obj
    else:
        raise TypeError('argument 1 must be a ChaChaCTX obj- ' \
                        + 'either AEAD.main or AEAD.header')
        
    nonce = hexbytes_to_intarray(nonce)
    if len(nonce) > CHACHA_NONCELEN:    # 8 bytes
        raise TypeError('nonce cannot exceed 8 bytes')
    ivarray = ctypes.c_ubyte * CHACHA_NONCELEN
    iv = ivarray(0 * CHACHA_NONCELEN)
    iv = intarray_to_carray(nonce, iv)
    
    counter = counter
        
    __check_exit(libcha.chacha_ivsetup(ctypes.byref(chacha_ctx), iv, counter))

    return chacha_ctx


#void chacha_keysetup(chacha_ctx *x, const u8 *k, u32 kbits)
#
def chacha_keysetup(chachactx_obj=None, key=None):
    """ Receive a mandatory 32 byte key (although the C function 
        allows 16 bytes) and pack and return this as a chacha ctx struct.
        A ctx obj is instantiated if none is passed. 
    """
    if key == None:
        raise ValueError("'key' argument is required")
    elif len(key) != POLY1305_KEYLEN:   # 32 bytes
        raise ValueError("key length must be 32 bytes")
        
    if chachactx_obj:
        if isinstance(chachactx_obj, ChaChaCTX):
            chacha_ctx = chachactx_obj
    else:
        chacha_ctx = ChaChaCTX()

    k = hexbytes_to_intarray(key)
    keyarray = ctypes.c_ubyte * POLY1305_KEYLEN
    key = keyarray(0 * POLY1305_KEYLEN)
    key = intarray_to_carray(k, key)
    
    kbits = POLY1305_KEYLEN * 8 # 256 bits altho C keysetup() also accepts 128

    __check_exit(libcha.chacha_keysetup(ctypes.byref(chacha_ctx), key, kbits))

    return chacha_ctx


#void chacha_encrypt_bytes(chacha_ctx *x, const u8 *m, u8 *c, u32 bytes)
#
def chacha_encrypt_bytes(chachactx_obj, inbuf=512):
    """ Receive a prepared ChaChaCTX object and return a keystream.
        chachactx_obj is prepared via chacha_keysetup() and 
        chacha_ivsetup() above.
    """
    if not isinstance(chachactx_obj, ChaChaCTX):
        raise TypeError("argument 1 must be a ChaChaCTX obj")
    
    #TODO is expected inbuf always 512 bytes?
    streambytes = inbuf
    
    # prepare keystream containers
    keystrm = ctypes.c_uint8 * streambytes
    keystreamin = keystrm(0 * streambytes)
    keystreamout = keystrm(0 * streambytes)
    
    __check_exit(libcha.chacha_encrypt_bytes(ctypes.byref(chachactx_obj),
                                             keystreamin,
                                             keystreamout,
                                             streambytes))
    
    #TODO ascertain desired return format
    keystream = array_to_hexstr(keystreamout)

    return keystream


#void poly1305_auth(unsigned char out[POLY1305_TAGLEN], 
#                   const unsigned char *m,
#                   size_t inlen, 
#                   const unsigned char key[POLY1305_KEYLEN])
#
def poly1305_auth(pinput, pkey):
    """ Return Poly1305 tag """
    #assert len(pkey) == 32
    if len(pkey) != 32:
        print('* poly1305_auth() Warning: key len %i != 32 bytes' % len(pkey))
    k = hexbytes_to_intarray(pkey)
    keyarray = ctypes.c_ubyte * POLY1305_KEYLEN
    key = keyarray(0 * POLY1305_KEYLEN)
    key = intarray_to_carray(k, key)    
    
    inputlen = ctypes.c_int(len(pinput))
    
    #TODO constant 32 byte input?
    p_in = hexbytes_to_intarray(pinput)
    inarray = ctypes.c_ubyte * 32
    polyin = inarray(0 * 32)
    poly_input = intarray_to_carray(p_in, polyin)

    tagarray = ctypes.c_ubyte * POLY1305_TAGLEN
    tag = tagarray(0 * POLY1305_TAGLEN)
                
    libpoly.poly1305_auth(ctypes.byref(tag), poly_input, inputlen, key)
    
    #TODO ascertain desired return format
    taghex = array_to_hexstr(tag)

    return taghex


#int chacha20poly1305_init(struct chachapolyaead_ctx *ctx,
#                           const uint8_t *key,
#                           int keylen)
#
def chacha20poly1305_init(key):
    """ Initialize keys K_1 and K_2 and return encapsulated in 
        struct chachapolyaead_ctx. 
        key arg consists of two 256 bit keys, concatenated.
    """
    if len(key) != POLY1305_KEYLEN * 2:     # 64 bytes
        #raise ValueError('key material must be 64 bytes')
        print('* Warning: key material should be 64 bytes')
    k = hexbytes_to_intarray(key)
    keyarray = ctypes.c_uint8 * (POLY1305_KEYLEN * 2)
    key = keyarray(0 * (POLY1305_KEYLEN * 2))
    key = intarray_to_carray(k, key)
    
    keylen = len(key)

    aead_ctx = AEAD()
    
    __check_exit(libaead.chacha20poly1305_init(ctypes.byref(aead_ctx),
                                          key,
                                          keylen))

    return aead_ctx


#int chacha20poly1305_crypt(struct chachapolyaead_ctx *ctx, 
#                           uint32_t seqnr,
#                           uint8_t *dest, 
#                           const uint8_t *src, 
#                           uint32_t len,
#                           uint32_t aadlen, 
#                           int is_encrypt)
#
def chacha20poly1305_crypt(aead_obj, inbuf=None, nonce=0, alen=None,
                            is_encrypt=1):

    if is_encrypt not in [0, 1]:
        raise ValueError('is_encrypt must be 1 (to encrypt) or 0 (decrypt)')
    
    assert isinstance(aead_obj, AEAD)
    #TODO vaildate nonce type
    seqnr = ctypes.c_uint32(nonce)
    
    if not alen:
        alen = 0
    else:
        # validate alen type and sanity (try: expect preferable here?)
        pass

    # Encrypt data prep
    if is_encrypt == 1:
        # cast input as C array
        inlen = len(inbuf)
        plaintext = hexbytes_to_intarray(inbuf)
        srcarray = ctypes.c_uint8 * inlen
        src = srcarray(0 * inlen)
        src = intarray_to_carray(plaintext, src)

        ciphertext = ctypes.c_uint8 * (inlen + POLY1305_TAGLEN)
        dest = ciphertext(0 * (inlen + POLY1305_TAGLEN))

    # Decrypt data prep
    elif is_encrypt == 0:
        #TODO validate inbuf
        inbuf = hexbytes_to_intarray(inbuf)
        inlen = len(inbuf)
        srctype = ctypes.c_uint8 * inlen
        srcarray = srctype(0 * inlen)
        src = intarray_to_carray(inbuf, srcarray)
        outlen = inlen - POLY1305_TAGLEN
        
        plaintext = ctypes.c_uint8 * outlen
        dest = plaintext(0 * outlen)
        inlen = outlen

    mlen = ctypes.c_uint32(inlen - alen)
    aadlen = ctypes.c_uint32(alen)

    # Encrypt
    if is_encrypt == 1:
            
        __check_exit(libaead.chacha20poly1305_crypt(ctypes.byref(aead_obj),
                                        seqnr,
                                        ctypes.byref(dest),
                                        src,
                                        mlen,
                                        aadlen,
                                        is_encrypt))
        # ascertain return objs and formats
        #return array_to_hexstr(dest)
        return intarray_to_bytestr(dest)
    
    # Decrypt
    elif is_encrypt == 0:

        __check_exit(libaead.chacha20poly1305_crypt(ctypes.byref(aead_obj),
                                        seqnr,
                                        ctypes.byref(dest),
                                        ctypes.byref(src),
                                        mlen,
                                        aadlen,
                                        is_encrypt))
        # ascertain return objs and formats
        #return array_to_hexstr(dest)
        return intarray_to_bytestr(dest)


#int chacha20poly1305_get_length( struct chachapolyaead_ctx *ctx,
#                                 uint32_t *len_out, 
#                                 uint32_t seqnr,
#                                 const uint8_t *ciphertext, 
#                                 uint32_t len )
#
def chacha20poly1305_get_length(aead_obj, ciphertext, nonce=0, alen=0):
    """ Decrypt and extract the encrypted packet length 
        Receives ciphertext as a byte string.
        Returns ?
    """
    # the provided aead_obj must conform to AEAD class structure
    if not isinstance(aead_obj, AEAD):
        print('provided aead object is invalid')
        sys.exit(1)
    # additional data length >= 4
    if alen < 4:
        print('additional data length must be at least 4 bytes')
        sys.exit(1)
    
    #cast cyphertext as a C array
    inbuf = hexbytes_to_intarray(ciphertext)
    inlen = len(inbuf)
    srctype = ctypes.c_uint8 * inlen
    srcarray = srctype(0 * inlen)
    src = intarray_to_carray(inbuf, srcarray)

    #TODO validate nonce
    seqnr = ctypes.c_uint32(nonce)
    aadlen = ctypes.c_uint32(alen)
    len_out = ctypes.c_uint8(0)

    __check_exit(libaead.chacha20poly1305_get_length(ctypes.byref(aead_obj),
                                                ctypes.byref(len_out),
                                                seqnr,
                                                ctypes.byref(src),
                                                aadlen))

    return len_out.value


