#!/usr/bin/python

import base64
from Crypto.Cipher import AES,ARC4
import binascii,sys


BS = 16
unpad = lambda s : s[:-ord(s[len(s)-1:])]

#thanks  https://stackoverflow.com/a/12525165 for crypto snippet
class AESCipher:
    def __init__( self, key ):
        self.key = key

    def decrypt( self, enc, mode ):
        if mode == "ENCMTHD_2":
                cipher = AES.new(self.key, AES.MODE_ECB )
        elif mode == "ENCMTHD_3":
                iv = b"\x00" * 16
                cipher = AES.new(self.key, AES.MODE_CBC, iv )

        else:
            print("Invalid mode")
            return False

        return unpad(cipher.decrypt( enc ))


def main():
        #Keys hardcoded into netscaler libnscli90.so
        aeskey = binascii.unhexlify("351CBE38F041320F22D990AD8365889C7DE2FCCCAE5A1A8707E21E4ADCCD4AD9")
        rc4key = binascii.unhexlify("2286da6ca015bcd9b7259753c2a5fbc2")

        if len(sys.argv) == 3:
            ciphertext = sys.argv[1]
            mode = sys.argv[2]

            if mode == "ENCMTHD_3" or mode == "ENCMTHD_2":
                c = AESCipher(aeskey)
                decoded = c.decrypt(binascii.unhexlify(ciphertext),mode)
                if mode == "ENCMTHD_3":
                        print(decoded[16:])
                else:
                        print(decoded)

            elif mode == "ENCMTHD_1": #old rc4 mode
                out_cipher = ARC4.new(rc4key)
                decoded = out_cipher.decrypt(binascii.unhexlify(ciphertext))
                print(decoded)


if __name__ == "__main__":
        main()