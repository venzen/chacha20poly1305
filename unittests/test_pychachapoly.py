#!/usr/bin/env python3
""" 
Unit tests for pychachapoly.

pychachapoly is a Python wrapper for the chacha20poly1305@openssh library
implementation written by Jonas Schnelli and available at:
    
https://github.com/jonasschnelli/chacha20poly1305

This wrapper copyright (c) 2016, Venzen Khaosan
Distributed under the MIT software license, see the accompanying
file COPYING or http://www.opensource.org/licenses/mit-license.php
"""

import unittest
import binascii

# The source of each test vector below is given as key TV_SOURCE and
# each dictionary of vectors is named (with sequential increment) in key NAME

ChaCha20_TVs = [
    {   'NAME':          'IETF ChaCha20 test 1',
        'TV_SOURCE':     'https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7',
        'KEY':           '0000000000000000000000000000000000000000000000000000000000000000',
        'NONCE':         '0000000000000000',
        'KEYSTREAM':     '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7'\
                         'da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'  },
                       
    {   'NAME':          'IETF ChaCha20 test 2',
        'TV_SOURCE':     'https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7',
        'KEY':           '0000000000000000000000000000000000000000000000000000000000000001',
        'NONCE':         '0000000000000000',
        'KEYSTREAM':     '4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41'\
                         'bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963'  },
                       
    {   'NAME':          'IETF ChaCha20 test 3',
        'TV_SOURCE':     'https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7',
        'KEY':           '0000000000000000000000000000000000000000000000000000000000000000',
        'NONCE':         '0000000000000001',
        'KEYSTREAM':     'de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031'\
                         'e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3'          },
                       
    {   'NAME':          'IETF ChaCha20 test 4',
        'TV_SOURCE':     'https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7',
        'KEY':           '0000000000000000000000000000000000000000000000000000000000000000',
        'NONCE':         '0100000000000000',
        'KEYSTREAM':     'ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32'\
                         '111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b', },
                       
    {   'NAME':         'IETF ChaCha20 test 5',
        'TV_SOURCE':    'https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7',
        'KEY':          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'NONCE':        '0001020304050607',
        'KEYSTREAM':    'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56'\
                        'f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f1'\
                        '5916155c2be8241a38008b9a26bc35941e2444177c8ade6689de9526'\
                        '4986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e'\
                        '09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a4750'\
                        '32b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c5'\
                        '07b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f7'\
                        '6dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2'\
                        'ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab7'\
                        '8fab78c9'  }
]
     
Poly1305_TVs = [
    {   'NAME':          'IETF Poly1305 test 1',
        'TV_SOURCE':     'https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7',
        'INPUT':         '0000000000000000000000000000000000000000000000000000000000000000',
        'KEY':           '746869732069732033322d62797465206b657920666f7220506f6c7931333035',
        'TAG':           '49ec78090e481ec6c26b33b91ccc0307' },
        
    {   'NAME':          'IETF Poly1305 test 2',
        'TV_SOURCE':     'https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7',
        'INPUT':         '48656c6c6f20776f726c6421',
        'KEY':           '746869732069732033322d62797465206b657920666f7220506f6c7931333035',
        'TAG':           'a6f745008f81c916a20dcc74eef2b2f0' }
]

AEAD_ChaCha20_Poly1305_TVs = [
    {  'NAME':          'Repository native ChaCha20_Poly1305 AEAD construction test 1',
       'TV_SOURCE':     'https://github.com/jonasschnelli/chacha20poly1305/blob/master/tests.c',
       'KEY':           '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\
                        '0000000000000000000000000000000000000000000000000000000000000000',
       'KEYARR':        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                         0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                         0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
       'INPUT':         'f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b'\
                        '733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a'\
                        '26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1c'\
                        'c118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7'\
                        'c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c'\
                        '566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f7'\
                        '6dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5a'\
                        'aae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9',
                        # first 4 bytes of INPUTARR extracted to ADARR below
       'INPUTARR':      [0xf1, 0x95, 0xe6, 0x69, 0x82, 0x10, 0x5f, 0xfb,
                         0x64, 0x0b, 0xb7, 0x75, 0x7f, 0x57, 0x9d, 0xa3, 0x16, 0x02, 0xfc, 0x93,
                         0xec, 0x01, 0xac, 0x56, 0xf8, 0x5a, 0xc3, 0xc1, 0x34, 0xa4, 0x54, 0x7b,
                         0x73, 0x3b, 0x46, 0x41, 0x30, 0x42, 0xc9, 0x44, 0x00, 0x49, 0x17, 0x69,
                         0x05, 0xd3, 0xbe, 0x59, 0xea, 0x1c, 0x53, 0xf1, 0x59, 0x16, 0x15, 0x5c,
                         0x2b, 0xe8, 0x24, 0x1a, 0x38, 0x00, 0x8b, 0x9a, 0x26, 0xbc, 0x35, 0x94,
                         0x1e, 0x24, 0x44, 0x17, 0x7c, 0x8a, 0xde, 0x66, 0x89, 0xde, 0x95, 0x26,
                         0x49, 0x86, 0xd9, 0x58, 0x89, 0xfb, 0x60, 0xe8, 0x46, 0x29, 0xc9, 0xbd,
                         0x9a, 0x5a, 0xcb, 0x1c, 0xc1, 0x18, 0xbe, 0x56, 0x3e, 0xb9, 0xb3, 0xa4,
                         0xa4, 0x72, 0xf8, 0x2e, 0x09, 0xa7, 0xe7, 0x78, 0x49, 0x2b, 0x56, 0x2e,
                         0xf7, 0x13, 0x0e, 0x88, 0xdf, 0xe0, 0x31, 0xc7, 0x9d, 0xb9, 0xd4, 0xf7,
                         0xc7, 0xa8, 0x99, 0x15, 0x1b, 0x9a, 0x47, 0x50, 0x32, 0xb6, 0x3f, 0xc3,
                         0x85, 0x24, 0x5f, 0xe0, 0x54, 0xe3, 0xdd, 0x5a, 0x97, 0xa5, 0xf5, 0x76,
                         0xfe, 0x06, 0x40, 0x25, 0xd3, 0xce, 0x04, 0x2c, 0x56, 0x6a, 0xb2, 0xc5,
                         0x07, 0xb1, 0x38, 0xdb, 0x85, 0x3e, 0x3d, 0x69, 0x59, 0x66, 0x09, 0x96,
                         0x54, 0x6c, 0xc9, 0xc4, 0xa6, 0xea, 0xfd, 0xc7, 0x77, 0xc0, 0x40, 0xd7,
                         0x0e, 0xaf, 0x46, 0xf7, 0x6d, 0xad, 0x39, 0x79, 0xe5, 0xc5, 0x36, 0x0c,
                         0x33, 0x17, 0x16, 0x6a, 0x1c, 0x89, 0x4c, 0x94, 0xa3, 0x71, 0x87, 0x6a,
                         0x94, 0xdf, 0x76, 0x28, 0xfe, 0x4e, 0xaa, 0xf2, 0xcc, 0xb2, 0x7d, 0x5a,
                         0xaa, 0xe0, 0xad, 0x7a, 0xd0, 0xf9, 0xd4, 0xb6, 0xad, 0x3b, 0x54, 0x09,
                         0x87, 0x46, 0xd4, 0x52, 0x4d, 0x38, 0x40, 0x7a, 0x6d, 0xeb, 0x3a, 0xb7,
                         0x8f, 0xab, 0x78, 0xc9],
        'NONCE':        '64',
        'NONCEINT':     [0x64],
        'AD':           'ff000000',
        'ADARR':        [0xff, 0x00, 0x00, 0x00],
        'OUTPUT':       'd633f688c0e9757879fa7c1be2979e6577c95ae77f2d299c4bd3a5fdb04df8d6'\
                        '2f5bd82afcdc3ffcd7fccc8a8116182078ea28f58f0f8d5d37fa6caab5a66c93'\
                        '42d34729701c34c6b664099cf29a3571e7654b3af5d8743f6a30ed25daa8af0a'\
                        '1a042310485a8270ed16203fe440e699d7ec9531d35ee298f331cc0f435cd849'\
                        '9157236a25d06c71c87bc9265adc45e56a1f6f59c8252b01370c0d08c7525876'\
                        'f8c02d7413919244bb026cbaeb8acb73b3f60b2d0b885a7e29adca652698eaa8'\
                        '0dea0da785519d9beb115a70fff9248f88d90ae4481a7e8a539398add8ee0bbe'\
                        'af0b4b316f209b6982218f080209514e91d0a6d60e33743774def1523f8f01d4'\
                        'bf746b4257e3bd6f3bc268b8' },
                        
    {  'NAME':          'RFC7539 ChaCha20_Poly1305 AEAD construction test 2',
       'TV_SOURCE':     'https://tools.ietf.org/html/rfc7539#page-22',
       'INPUTTEXT':     "Ladies and Gentlemen of the class of '99: If I could "\
                        "offer you only one tip for the future, sunscreen would be it.",
       'INPUT':         '4c616469657320616e642047656e746c656d656e206f662074686520636c6173'\
                        '73206f66202739393a204966204920636f756c64206f6666657220796f75206f'\
                        '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73'\
                        '637265656e20776f756c642062652069742e',
       'AD':            '50515253c0c1c2c3c4c5c6c7',
       'ADARR':         [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7],
       'KEY':           '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
       'KEYARR':        [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                         0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                         0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                         0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f],
       'NONCE':         '070000004041424344454647',
       'NONCEARR ':     [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47],
       'OUTPUT':        'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63'\
                        'dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692'\
                        'ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff'\
                        '4def08e4b7a9de576d26586cec64b6116',
       'OUTPUTARR':     [0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
                         0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
                         0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
                         0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
                         0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
                         0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
                         0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
                         0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
                         0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
                         0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
                         0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
                         0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
                         0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
                         0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
                         0x61, 0x16],
       'TAG':           '1ae1b594f9e26a7e902ecbd060691',
       'TAGARR':        [0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
                         0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91] },
                         
    {  'NAME':          'IETF ChaCha20_Poly1305 AEAD construction test 3',
       'TV_SOURCE':     'https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7',
       'KEY':           '4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007',
       'INPUT':         '86d09974840bded2a5ca',
       'NONCE':         'cd7cf67be39c794a',
       'AD':            '87e229d4500845a079c0',
       'OUTPUT':        'e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6' }
]


class TestPyChaCha(unittest.TestCase):
    
    def test_chacha20(self):
        print('TestPyChaCha')
        for tv in ChaCha20_TVs:
            print('%s/%i' % (tv['NAME'], len(ChaCha20_TVs)))
            key = binascii.unhexlify(tv['KEY'])
            nonce = binascii.unhexlify(tv['NONCE'])
            # expected_keystream remains hexstr since chacha_encrypt_bytes() 
            # returns a hexstr
            expected_keystream = tv['KEYSTREAM']
            
            keyobj = pychachapoly.chacha_keysetup(key=key)
            print('keysetup', keyobj)
            self.assertIsInstance(keyobj, pychachapoly.ChaChaCTX)
            
            keyobj = pychachapoly.chacha_ivsetup(keyobj,nonce)
            print('ivysetup', keyobj)
            self.assertIsInstance(keyobj, pychachapoly.ChaChaCTX)
            
            keystream = pychachapoly.chacha_encrypt_bytes(keyobj)
            print('keystream', keystream)
            self.assertTrue(keystream.startswith(expected_keystream))
            
            print('- test passed\n')


class TestPyAuthPoly(unittest.TestCase):
    
    def test_auth_poly1305(self):
        print('TestPyAuthPoly')
        for tv in Poly1305_TVs:
            print('%s/%i' % (tv['NAME'], len(Poly1305_TVs)))
            pinput = binascii.unhexlify(tv['INPUT'])
            key = binascii.unhexlify(tv['KEY'])
            # expected_tag remains hexstr since poly_auth() returns a hexstr
            expected_tag = tv['TAG']
            
            tag = pychachapoly.poly1305_auth(pinput, key)
            self.assertEqual(tag, expected_tag)
            
            print('- test passed\n')


class TestPyChaChaPolyAEAD(unittest.TestCase):
    
    def test_chacha20poly1305_aead(self):
        print('TestPyChaChaPolyAEAD')
        for tv in AEAD_ChaCha20_Poly1305_TVs:
            print('%s/%i' % (tv['NAME'], len(AEAD_ChaCha20_Poly1305_TVs)))
            key = binascii.unhexlify(tv['KEY'])
            input_ = binascii.unhexlify(tv['INPUT'])
            nonce = int('0x%s' % tv['NONCE'], 0)
            ad = binascii.unhexlify(tv['AD'])
            alen = len(ad)
            print('ad (%i bytes):' % alen, tv['AD'])
            # accommodate Python 2 lack of bytes encoding
            if sys.version_info.major == 3:
                expected_output = bytes(tv['OUTPUT'], 'utf-8')
            else:
                expected_output = tv['OUTPUT']
            
            print('> Init keys')
            aead_ctx = pychachapoly.chacha20poly1305_init(key)
            self.assertIsInstance(aead_ctx, pychachapoly.AEAD)
            
            #if tv == 'RFC7539 ChaCha20_Poly1305 AEAD construction test 2':
            #    input_ = ad + input_
            
            # Encrypt
            print('> Encrypt')
            enc_output = pychachapoly.chacha20poly1305_crypt(aead_ctx, 
                                                         inbuf=input_, 
                                                         nonce=nonce, 
                                                         alen=alen, 
                                                         is_encrypt=1)
                                                         
            print('len input_            %5.0f' % len(input_))
            print('len tag             + %5.0f' % pychachapoly.POLY1305_TAGLEN)
            print('len enc_output      = %5.0f' % len(enc_output))
            print('len expected_output = %5.0f' % len(binascii.unhexlify(expected_output)))
            self.assertEqual(binascii.hexlify(enc_output), expected_output)

            # len_out
            print('> Encrypted len_out')
            len_out = pychachapoly.chacha20poly1305_get_length(aead_ctx, 
                                                               enc_output,
                                                               nonce=nonce,
                                                               alen=alen)
            print('len_out             = %5.0f' % len_out)
            # TODO len_out vectors
            #self.assertEqual(len_out, expected_len_out)
            
            # Decrypt 
            print('< Decrypt')
            dec_output = pychachapoly.chacha20poly1305_crypt(aead_ctx,
                                                         inbuf=enc_output,
                                                         nonce=nonce,
                                                         alen=alen,
                                                         is_encrypt=0)
            
            # RFC7539 ChaCha20_Poly1305 AEAD construction test 2 does not 
            # return provided encrypt OUTPUT but decrypts enc_output to 
            # correct plaintext (provided INPUT) as illustrated by 
            # uncommenting the following line:
            #print('unhex dec_output', binascii.hexlify(dec_output))
            print('len dec_output      = %5.0f' % len(dec_output))
            print('len input_          = %5.0f' % len(input_))
            self.assertEqual(dec_output, input_)
            
            print('- test passed\n')


if __name__ == '__main__':
    
    if __package__ is None:
        import sys
        from os import path
        sys.path.append(path.dirname(path.dirname( path.abspath(__file__))))
        import pychachapoly
    else:
        from .. import pychachapoly
        
    unittest.main()

