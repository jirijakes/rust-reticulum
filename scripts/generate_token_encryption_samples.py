from RNS.Cryptography import Token
from RNS.Cryptography import HMAC
from RNS.Cryptography import PKCS7
from RNS.Cryptography.AES import AES_128_CBC
import os, random

def hex(b):
    return ''.join('{:02x}'.format(x) for x in b)

print("[")
for _ in range(200):
    data = os.urandom(random.randint(0, 512))
    token = Token(os.urandom(32))
    iv = os.urandom(16)

    ciphertext = AES_128_CBC.encrypt(plaintext = PKCS7.pad(data), key = token._encryption_key, iv = iv,)

    signed_parts = iv + ciphertext
  
    enc = signed_parts + HMAC.new(token._signing_key, signed_parts).digest()

    print('("%s", "%s", "%s", "%s", "%s"),' % (hex(token._signing_key), hex(token._encryption_key), hex(iv), hex(data), hex(enc)))
print("]")
