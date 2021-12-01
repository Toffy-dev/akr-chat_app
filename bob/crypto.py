from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pd
import hashlib

FORMAT = 'ascii'
IV = b'\x0bX\xae\xe3y\xd32\xb5B\xd7\xf3\xf8\r\xe1s\x06'
# vygeneruj tajný klíč
def encrypt_AES(secret_key, iv, message) -> bytes:
    # zahešuj tajný klíč pro AES
    hash = hashlib.sha256()
    hash.update(secret_key)
    hashed_key = hash.digest()
    # zašifruj zprávu AES a zahešovaným tajným klíčem
    cipher = Cipher(algorithms.AES(hashed_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    # přidaní místa pro nasobky 16ky pro funkci aes
    padder = pd.PKCS7(128).padder()
    padded_data = padder.update(message.encode(FORMAT))
    padded_data += padder.finalize()
    message = encryptor.update(padded_data) + encryptor.finalize()
    return message

    # zašifruj klíč RSA pomocí veřejného klíče
def encrypt_RSA(secret_key, public_key):
    msg_rsa = secret_key
    ciphertext = public_key.encrypt(
        msg_rsa,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext
# -- dešifrovaní --

def decrypt(private_key, ciphertext, iv, message) -> bytes:
# dešifruj klíč pomocí soukromého klíče
    dec_rsa = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # zahešuj klíč
    hash = hashlib.sha256()
    hash.update(dec_rsa)
    AES_hash_key = hash.digest()

    # dešifruj zprávu pomocí aes a zahešovaného klíče
    decryptor = Cipher(algorithms.AES(AES_hash_key), modes.CBC(iv)).decryptor()
    # vypiš zprávu
    to_unpadd = decryptor.update(message)
    unpadder = pd.PKCS7(128).unpadder()
    data = unpadder.update(to_unpadd)
    message = data + unpadder.finalize()
    #print(message.decode(FORMAT))
    return message.decode(FORMAT)

def load_pub_key():
    # load public key from certificate
    with open("alice.crt", "rb") as key_file:
        cert_obj = x509.load_pem_x509_certificate(key_file.read(), default_backend())
        public_key = cert_obj.public_key()
    return public_key

def load_sec_key():
    # load secret key from file
    with open("bob.key", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b"heslo123",
        )
    return private_key
