import socket
import threading

#######################################################
#                   INITIALIZATION
#######################################################
FORMAT = 'utf-8'

PORT = 5050
SERVER = "127.0.0.1"
ADDR = (SERVER,PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
server.listen()

client_list = []
nicknames = []
#######################################################

#Broadcast
def broadcast(msg):
    for client in client_list:
        client.send(msg)

#handle
def handle_client(client): #manejador de la conexion con el cliente
    while True:
        try:
            message = client.recv(1024)
            print(f"$ {nicknames[client_list.index(client)]}")
            broadcast(message)

        except:
            index = client_list.index(client)
            client_list.remove(client)
            nickname = nicknames[index]
            broadcast(f"{nickname} ha dejado el chat...".encode(FORMAT))
            nicknames.remove(nickname)
            client.close()
            break
 
#receive
def receive():
    while True:
        print("[STARTING] Server listening ...")
        client, addr = server.accept()
        print(f'Connected with {addr}')

        client.send("Nickname?: ".encode(FORMAT))
        nickname = client.recv(1024)

        client_list.append(client)
        nicknames.append(nickname)

        broadcast(f"{nickname} ha entrado al chat!\n".encode(FORMAT))
        client.send("Connected to the server.".encode(FORMAT))

        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

def main():    
    receive()
if __name__ == "__main__":
    main()





