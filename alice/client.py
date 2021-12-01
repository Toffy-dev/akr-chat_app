import os
import socket
import threading
from crypto import IV, decrypt, encrypt_AES, encrypt_RSA, load_pub_key, load_sec_key
from cryptography.hazmat.primitives.asymmetric import rsa

FORMAT = 'ascii'



class Client:
    
    private_key = load_sec_key()
    public_key = load_pub_key()
    secret_key = os.urandom(32)
    iv = IV
    
    made_message = ''
    # Připojení na server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('172.104.251.45', 55555))
    def __init__(self):
        # nastavení jména
        self.nickname = 'Alice'

    # poslouchání serveru
    def receive(self):
        while True:
            try:
                #obdržení zprávy
                message = self.client.recv(4096)
                if message == self.made_message:
                    continue
                message = message.decode(FORMAT)

                if message == 'NICK':
                    self.client.send(self.nickname.encode(FORMAT))
                #pokud posíláme více proměných naráz
                elif len(message.split('\n')) == 2:
                    msg, ciphertext = message.split('\n')
                    # musíme odstranit ze stringu znak pro bytes a naslendně se zbavit \\ a nahradit za \
                    msg = msg[2:-1]
                    msg = msg.encode(FORMAT)
                    msg = msg.decode('unicode_escape').encode("raw_unicode_escape")
                    ciphertext = ciphertext[2:-1]
                    ciphertext = ciphertext.encode(FORMAT)
                    ciphertext = ciphertext.decode('unicode_escape').encode("raw_unicode_escape")

                    print(decrypt(self.private_key, ciphertext, self.iv, msg))
                else:
                    print(message)
            except:
                # ukončení spojení
                print("An error occured!")
                self.client.close()
                break

    # Odesílání zpráv na server
    def write(self):
        while True:
            self.made_message = '{}: {}'.format(self.nickname, input(''))
            print(self.made_message)
            self.made_message = encrypt_AES(self.secret_key, self.iv, self.made_message)
            ciphertext = encrypt_RSA(self.secret_key, self.public_key)
            self.made_message = str.encode("\n".join([str(self.made_message), str(ciphertext)]))
            self.client.sendall(self.made_message)


    def run(self):
        # zahájení spojení
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        write_thread = threading.Thread(target=self.write)
        write_thread.start()

if __name__ == '__main__':
    app = Client()
    app.run()
