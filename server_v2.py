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
        print("[STARTING] Server listening ...")
        while(True):
            if self.status:
                consoleCommand = str(input(chr(27)+'[1;37m'+'\n[Server]$ '))
                if consoleCommand == "":
                    pass
                elif consoleCommand == "help":
                    print(chr(27)+'[1;33m',end="")
                    print("\n\t[*]Lista de comandos del servidor[*]")
                    print("\t[1]exit --> Salir del servidor")
                    print("\t[2]count --> Cantidad de usuarios en el servidor")
                    print("\t[3]list --> Lista a los usuarios en el servidor")

                elif consoleCommand == "list":
                    print(chr(27)+'[1;33m',end="")
                    print(f"[*] Hay {len(client_list)} usuarios en el servidor [*]")

                elif consoleCommand == "count":
                    print(chr(27)+'[1;33m',end="")
                    print("[*] Los usuarios conectados actualmente son: [*]")
                    for num, name in enumerate(nicknames):
                        print(f"[{num + 1}] {name}")

                elif consoleCommand == "exit":
                    print(chr(27)+'[1;31m',end="")
                    print("[-] Saliendo del servidor")
                    os._exit(0)

#Broadcast
def broadcast(msg):
    for client in client_list:
        client.send(msg)

def close(client):
    index = client_list.index(client)
    client_list.remove(client)
    nickname = nicknames[index]
    print(chr(27)+'[1;31m',end="")
    print(f"[-] Se ha desconectado {nickname}...")
    print(chr(27)+'[0;37m',end="")
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
            print(chr(27)+'[1;33m',end="")
            print(f"$ {nicknames[client_list.index(client)]}")
            broadcast(message)

        except:
            close(client)
            break

#receive
def receive():
    while True:
        client, addr = server.accept()
        print(f'Connected with {addr}')

        client.send("Nickname?: ".encode(FORMAT))
        nickname = client.recv(1024)

        client_list.append(client)
        nicknames.append(nickname)

        print(chr(27)+'[1;32m',end="")
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
