#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import base64
# sys.modules['Crypto'] = crypto
from Crypto.Cipher import AES
from Crypto import Random

# from Crypto.Hash import SHA
# from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
# from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
# from Crypto.PublicKey import RSA

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))
        # return base64.b64encode(cipher.encrypt( raw ) )

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))


'''
class RSACipher:
    # load公钥和密钥
    def __init__(self,publickey,privatekey):
        self.random_generator = Random.new().read
        with open(publickey) as publickfile:
            p = publickfile.read()
            self.pubkey = p
 
        with open(privatekey) as privatefile:
            p = privatefile.read()
            self.privkey = p
           
    def generatorPEM(self):
        
        rsa = RSA.generate(1024,self.random_generator)   #默认也是输入一个随机数
        private_pem = rsa.exportKey('PEM')      #默认也是PEM
        with open('private.pem', 'w') as f:
            f.write(private_pem)
        public_pem = rsa.publickey().exportKey('PEM')
        with open('public.pem', 'w') as f:
            f.write(public_pem)

    def encrypt(self,encryptbuf):
        rsakey = RSA.importKey(self.pubkey)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        cipher_buf = base64.b64encode(cipher.encrypt(encryptbuf))
        #print cipher_buf
        return cipher_buf


    def decrypt(self,decryptbuf):

        rsakey = RSA.importKey(self.privkey)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        buf = cipher.decrypt(base64.b64decode(decryptbuf), self.random_generator)
        #print buf
        return buf

import binascii
'''
if __name__ == '__main__':
    # print chr(16-4%16)
    # print binascii.b2a_hex(u"在此处为应用程序的行为编写代码".encode("gbk"))
    # print binascii.b2a_hex(u"在此处为应用程序的行为编写代码".encode("utf-8"))
    print("AES")
    m = AESCipher("_YaraUploadPost_")
    test1 = m.encrypt("2017-05-10 11:19:03,246 INFO sqlalchemy.engine.base.Engine BEGIN (implicit)")
    print(test1)
    print(m.decrypt(test1))

    hbuf = open("./kfl_yara.tar.gz.aes", 'r')
    buf = hbuf.read()
    destr = m.decrypt(buf)
    hbuf2 = open("kfl_yara.tar.gz", 'wb')
    hbuf2.write(destr)
    hbuf2.close()

    # print "RSA"
    # n = RSACipher("public.pem","private.pem")
    # #n.generatorPEM()
    # en_rsa = n.encrypt("www.antiy.com")
    # print en_rsa
    # de_rsa = n.decrypt(en_rsa)
    # print de_rsa
