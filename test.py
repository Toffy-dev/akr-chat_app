
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

initialization_vector = os.urandom(16)

# zahešuj tajný klíč pro AES
hash = hashlib.sha256()
hash.update(secret_key)
hashed_key = hash.digest()
print(hashed_key)
# zašifruj zprávu AES a zahešovaným tajným klíčem
print(secret_key)
cipher = Cipher(algorithms.AES(hashed_key), modes.CBC(initialization_vector))
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
# -- dešifrovaní --
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
decryptor = Cipher(algorithms.AES(AES_hash_key), modes.CBC(initialization_vector)).decryptor()
# vypiš zprávu
print(message)
to_unpadd = decryptor.update(message)
print(to_unpadd)
unpadder = pd.PKCS7(128).unpadder()
data = unpadder.update(to_unpadd)
message = data + unpadder.finalize()
print(message.decode(FORMAT))

