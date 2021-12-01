import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pd
import hashlib

FORMAT = 'UTF-8'

# vygeneruj tajný klíč
secret_key = os.urandom(32)

iv = os.urandom(16)

# zahešuj tajný klíč pro AES
hash = hashlib.sha256()
hash.update(secret_key)
hashed_key = hash.digest()
print(hashed_key)
# zašifruj zprávu AES a zahešovaným tajným klíčem
print(secret_key)
cipher = Cipher(algorithms.AES(hashed_key), modes.CBC(iv))
encryptor = cipher.encryptor()
padder = pd.PKCS7(128).padder()
padded_data = padder.update(b"libovolne dlouha zprava jhhjhjhj")
padded_data += padder.finalize()
print(padded_data.decode(FORMAT))
message = encryptor.update(padded_data) + encryptor.finalize()
print(message)
# vygeneruj klíče pro RSA
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
print("privatekey :")
print(private_key)
# zašifruj klíč RSA pomocí veřejného klíče
msg_rsa = secret_key
ciphertext = public_key.encrypt(
    msg_rsa,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print('\n\n\n')
print(ciphertext)
# -- dešifrovaní --
msg = message
print(f'private_key: {type(private_key)}\nciphertext: {type(ciphertext)}\niv: {type(iv)}\nmessage: {type(msg)}')
print(f'private_key: {private_key}\nciphertext: {ciphertext}\niv: {iv}\nmessage: {msg}')
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
print(AES_hash_key)

# dešifruj zprávu pomocí aes a zahešovaného klíče
decryptor = Cipher(algorithms.AES(AES_hash_key), modes.CBC(iv)).decryptor()
# vypiš zprávu
print(message)
to_unpadd = decryptor.update(message)
print(to_unpadd)
unpadder = pd.PKCS7(128).unpadder()
data = unpadder.update(to_unpadd)
message = data + unpadder.finalize()
print(message.decode(FORMAT))

qwer1 = b'Uz=5\x8b\xc0\xe1{y\x05T\x07`\xf9\x0cp'
qwer2 = str(b'abcdef')
print("here:")
print(qwer2[2:-1].encode('utf-8'))
print(qwer1 == qwer2[2:-1].encode('utf-8'))
integer = int.from_bytes(qwer1, byteorder=sys.byteorder)
print(integer)
print(qwer1 == integer.to_bytes(1, 'big'))
print(integer.to_bytes(10, 'big'))