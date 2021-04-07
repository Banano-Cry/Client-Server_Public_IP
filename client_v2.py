import socket
import threading
import time
import sys
import os

try:
    HEADER = 64
    PORT = 15195
    FORMAT = 'utf-8'
    DISCONNECT_MESSAGE = "!DISCONNECT"
    SERVER = "3.142.81.166"
    ADDR = (SERVER,PORT)
    nickname = ""

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)

except ValueError as e:
    print(e)
    input()

def commands(command):

    if(command[1:] == "help"):
        print(chr(27)+'[1;33m',end="")
        print("\n\t[*]Lista de comandos[*]")
        print("\t[1]/exit --> Salir del servidor")

    if(command[1:] == "exit"):
        print("Cerrando conexion...")
        time.sleep(3)
        client.close()
        sys.exit(0)

def write():
    while True:
        msg = input("> ")

        if(len(msg) == 0):
            continue

        elif(msg[0] == "/"):
            commands(msg)

        else:
            data = f"$ {nickname}: {msg}"
            client.send(data.encode(FORMAT))

def receive():
    while True:
        try:
            msg = client.recv(1024).decode(FORMAT)

            if msg == "Nickname?: ":
                client.send(nickname.encode(FORMAT))
            else:
                print(chr(27)+'[0;37m',end="")
                if(len(msg) == 0):
                    print(chr(27)+'[1;31m',end="")
                    print("[-] Servidor desconectado")
                    client.close()
                    os._exit(0)
                else:
                    print(1)
                    print(chr(27)+'[1;33m'+msg)
                    '''
        except ConnectionAbortedError:
            client.close()
            os._exit(0)
            break
            '''
        except Exception as e:
            print(e)
            client.close()
            os._exit(0)
            break


def main():
    thread_recieve = threading.Thread(target=receive)
    thread_write = threading.Thread(target=write)

    thread_recieve.start()
    thread_write.start()

if __name__ == "__main__":
    nickname = input("Ingrese su nombre de usuario: ")
    main()
