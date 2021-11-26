import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AES:
    initialization_vector = os.urandom(16)

    def __init__(self):
        cipher = Cipher(algorithms.AES(key), modes.CBC(initialization_vector))

    def encrypt(self):
        ...

    def decrypt(self):
        ...



    key = os.urandom(32)
    print(key)
    initialization_vector = os.urandom(16)
    print(initialization_vector)

    # nastavení typu šifry
    cipher = Cipher(algorithms.AES(key), modes.CBC(initialization_vector))
    print(cipher)
    encryptor = cipher.encryptor()
    print(encryptor)
    ciphert_text = encryptor.update(b"a secret message")
    print(ciphert_text)
    decryptor = cipher.decryptor()
    print(decryptor.update(ciphert_text))
