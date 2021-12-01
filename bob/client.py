import os
import socket
import threading
from crypto import IV, decrypt, encrypt_AES, encrypt_RSA, load_pub_key, load_sec_key
from cryptography.hazmat.primitives.asymmetric import rsa

FORMAT = 'ascii'



class Client:
    #delete after
    private_key = load_sec_key()
    public_key = load_pub_key()
    secret_key = os.urandom(32)
    iv = IV
    #delete after
    made_message = ''
    # Connecting To Server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('172.104.251.45', 55555))
    def __init__(self):
        # Choosing Nickname
        self.nickname = 'Bob'

        # Listening to Server and Sending Nickname
    def receive(self):
        while True:
            try:
                # Receive Message From Server
                # If 'NICK' Send Nickname
                message = self.client.recv(4096)
                if message == self.made_message:
                    continue
                message = message.decode(FORMAT)

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
                    print(decrypt(self.private_key, ciphertext, self.iv, msg))
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
            self.made_message = '{}: {}'.format(self.nickname, input(''))
            print(self.made_message)
            self.made_message = encrypt_AES(self.secret_key, self.iv, self.made_message)
            ciphertext = encrypt_RSA(self.secret_key, self.public_key)
            self.made_message = str.encode("\n".join([str(self.made_message), str(ciphertext)]))
            self.client.sendall(self.made_message)


    def run(self):
        # Starting Threads For Listening And Writing
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        write_thread = threading.Thread(target=self.write)
        write_thread.start()

if __name__ == '__main__':
    app = Client()
    app.run()
