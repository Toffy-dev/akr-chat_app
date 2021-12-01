import os
import socket
import threading
from crypto import decrypt, encrypt_AES, encrypt_RSA
from cryptography.hazmat.primitives.asymmetric import rsa

FORMAT = 'ascii'

#delete after
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
secret_key = os.urandom(32)
iv = os.urandom(16)
#delete after

class Client:
    
    # Connecting To Server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 55555))
    def __init__(self):
        # Choosing Nickname
        self.nickname = input("Choose your nickname: ")

        # Listening to Server and Sending Nickname
    def receive(self):
        while True:
            try:
                # Receive Message From Server
                # If 'NICK' Send Nickname
                message = self.client.recv(4096).decode(FORMAT)
                if message == 'NICK':
                    self.client.send(self.nickname.encode(FORMAT))
                elif len(message.split('\n')) == 2:
                    msg, ciphertext = message.split('\n')
                    msg = msg[2:-1]
                    msg = msg.encode(FORMAT)
                    msg = msg.decode('unicode_escape').encode("raw_unicode_escape")
                    ciphertext = ciphertext[2:-1]
                    ciphertext = ciphertext.encode(FORMAT)
                    ciphertext = ciphertext.decode('unicode_escape').encode("raw_unicode_escape")
                    #print(f'private_key: {type(private_key)}\nciphertext: {type(ciphertext.encode(FORMAT))}\niv: {type(iv)}\nmessage: {type(msg.encode(FORMAT))}')
                    #print(f'private_key: {private_key}\nciphertext: {ciphertext.encode(FORMAT)}\niv: {iv}\nmessage: {msg.encode(FORMAT)}')
                    print(decrypt(private_key, ciphertext, iv, msg))
                else:
                    print(message)
            except:
                # Close Connection When Error
                print("An error occured!")
                self.client.close()
                break

    # Sending Messages To Server
    def write(self):
        while True:
            message = '{}: {}'.format(self.nickname, input(''))
            print(message)
            message = encrypt_AES(secret_key, iv, message)
            ciphertext = encrypt_RSA(secret_key, public_key)
            self.client.sendall(str.encode("\n".join([str(message), str(ciphertext)])))


    def run(self):
        # Starting Threads For Listening And Writing
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        write_thread = threading.Thread(target=self.write)
        write_thread.start()

if __name__ == '__main__':
    app = Client()
    app.run()
