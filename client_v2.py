import socket
import threading

try:

    HEADER = 64
    PORT = 8080
    FORMAT = 'utf-8'
    DISCONNECT_MESSAGE = "!DISCONNECT"
    SERVER = "tcp://4.tcp.ngrok.io"
    ADDR = (SERVER,PORT)
    nickname = ""

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)
except ValueError as e:
    print(e)
    input()

def write():
    while True:
        msg = input()
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