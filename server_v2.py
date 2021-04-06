import socket
import threading
import os

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

class serverThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self,name='Server')
        self.status = True
    def run(self):
        os.system('clear')
        while(True):
            if self.status:
                consoleCommand = str(input('[Server]$ '))
                if consoleCommand == "":
                    pass
                elif consoleCommand == "help":
                    print("\t\t[*]Lista de comandos del servidor[*]")
                    print("exit --> Salir del servidor")
                    print("count --> Cantidad de usuarios en el servidor")
                    print("list --> Lista a los usuarios en el servidor")

                elif consoleCommand == "list":
                    print(f"[*] Hay {len(client_list)} usuarios en el servidor [*]")

                elif consoleCommand == "count":
                    print("[*] Los usuarios conectados actualmente son: [*]")
                    for num, name in enumerate(nicknames):
                        print(f"[{num + 1}] {name}")

                elif consoleCommand == "exit":
                    os._exit(0)

#Broadcast
def broadcast(msg):
    for client in client_list:
        client.send(msg)

def close(client):
    index = client_list.index(client)
    client_list.remove(client)
    nickname = nicknames[index]
    print(f"[-] Se ha desconectado {nickname}...")
    broadcast(f"{nickname} ha dejado el chat...".encode(FORMAT))
    nicknames.remove(nickname)
    client.close()

#handle
def handle_client(client): #manejador de la conexion con el cliente
    while True:
        try:
            message = client.recv(1024)
            if message == b"":
                close(client)
                break
            print(f"$ {nicknames[client_list.index(client)]}")
            broadcast(message)

        except:
            close(client)
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

        print(f"[+] {nickname} ha entrado al chat!")
        broadcast(f"{nickname} ha entrado al chat!\n".encode(FORMAT))
        client.send("Connected to the server.".encode(FORMAT))

        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()
        command = input()
        if command == "/close":
            print("adios")

def main():
    server = serverThread()
    server.start()
    receive()
if __name__ == "__main__":
    main()
