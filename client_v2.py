import socket
import threading
import time
import sys

try:

    HEADER = 64
    PORT = 11538
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
            break
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
                print(f"{msg}\n")
        except ConnectionAbortedError:
            break
        except:
            print("Error")
            client.close()
            break


def main():
    thread_recieve = threading.Thread(target=receive)
    thread_write = threading.Thread(target=write)

    thread_recieve.start()
    thread_write.start()

if __name__ == "__main__":
    nickname = input("Ingrese su nombre de usuario: ")
    main()
