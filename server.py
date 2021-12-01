import socket
import threading


FORMAT = 'ascii'

#host = '127.0.0.1'
host = '172.104.251.45'
port = 55555

# zahajení serveru
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen(2)

clients = []
nicknames = []

# poslání zpravy všem klientům
def broadcast(message):
    for client in clients:
        client.send(message)


def handle(client):
    while True:
        try:
            # rozeslání zpáv
            message = client.recv(4096)
            broadcast(message)
        except:
            # odebiraní a ukončení komunikace s klientem
            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = nicknames[index]
            broadcast('{} left!'.format(nickname).encode(FORMAT))
            nicknames.remove(nickname)
            break


def receive():
    while True:
        # příjmání připojení
        client, address = server.accept()
        print("Connected with {}".format(str(address)))

        # žádost o zaslání jména a přidaní do listu
        client.send('NICK'.encode(FORMAT))
        nickname = client.recv(4096).decode(FORMAT)
        nicknames.append(nickname)
        clients.append(client)

        # vypiše a rozešle připojení clienta na server
        print("Nickname is {}".format(nickname))
        broadcast("{} joined!".format(nickname).encode(FORMAT))
        client.send('Connected to server!'.encode(FORMAT))

        # vytvoření vlákna pro clienty
        thread = threading.Thread(target=handle, args=(client,))
        thread.start()


receive()
