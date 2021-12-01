from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pd
import hashlib

FORMAT = 'UTF-8'
secret_key = os.urandom(32)
iv = os.urandom(16)
message = 'hello zprava'
# vygeneruj tajný klíč
def encrypt_AES(secret_key, iv, message):
    # zahešuj tajný klíč pro AES
    hash = hashlib.sha256()
    hash.update(secret_key)
    hashed_key = hash.digest()
    # zašifruj zprávu AES a zahešovaným tajným klíčem
    cipher = Cipher(algorithms.AES(hashed_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = pd.PKCS7(128).padder()
    padded_data = padder.update(message.encode(FORMAT))
    padded_data += padder.finalize()
    #print(padded_data.decode(FORMAT))
    message = encryptor.update(padded_data) + encryptor.finalize()
    return message
    # vygeneruj klíče pro RSA
    # private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # public_key = private_key.public_key()

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

def decrypt(private_key, ciphertext, iv, message):
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
    return message

#print(encrypt_AES(secret_key, iv, message))