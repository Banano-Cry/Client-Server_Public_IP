import socket
import threading
import os
import numpy as np

import cryptography
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
#######################################################
#                   INITIALIZATION
#######################################################
FORMAT = 'utf-8'

PORT = 5050
SERVER = "127.0.0.1"
ADDR = (SERVER,PORT)
LlaveSim = None
clave_rc4 = "elfinalito" #Clave de prueba

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
server.listen()

client_list = []
nicknames = []
#######################################################
################ RC4 #######################
def KSA(llave):
    longitud_llave = len(llave)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + llave[i%longitud_llave]) % 256
        S[i], S[j] = S[j], S[i]
    return S
def PRGA(S,n):
    i = 0
    j = 0
    llave = []

    while n>0:
        n = n - 1
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[ (S[i] + S[j]) % 256 ]
        llave.append(K)
    return llave

def llave_to_array(llave):
    return [ord(c) for c in llave]

def encriptarLlavePriv(llavePriv,claveRC):
    
    llave = llave_to_array(claveRC)
    S = KSA(llave)
    cadena_cifrante = np.array(PRGA(S, len(llavePriv)))
    #print("\nKeystream:")
    #print(cadena_cifrante)
    #llavePriv = np.array([chr(i) for i in llavePriv])
    llavePriv = np.array([i for i in llavePriv])

    cipher = cadena_cifrante ^ llavePriv #XOR dos arrays
    print(cipher)

    print("\nCipher en Hexadecimal:")
    print(cipher.astype(np.uint8).data.hex()) #imprime en hexadecimal
    llavePrivCifrada = cipher.astype(np.uint8).data.hex()
    return llavePrivCifrada


############### FIN RC4 ####################

#Generacion de llaves
def generarParLlaves():
    try:
        # Generates RSA Encryption + Decryption keys / Public + Private keys
        key = RSA.generate(1024)

        privateKey = key.export_key()
        publicKey = key.publickey().export_key()

        return privateKey, publicKey
    except Exception as e:
        print(e)
def generarLlaveSimetrica():
    LlaveSimetrica = Fernet.generate_key()
    return LlaveSimetrica
def broadcastLlaveSimetrica(LlaveSimetrica):
    try:
        broadcast(LlaveSimetrica)
    except Exception as e:
        print(e)

def encriptarLlaveSim(LlaveSim, LlavePublica):
    try:
            # Public encrypter object
            public_key = RSA.import_key(LlavePublica)
            public_crypter =  PKCS1_OAEP.new(public_key)
            # Encrypted fernet key
            key_encrypted = public_crypter.encrypt(LlaveSim)
            # Write encrypted fernet key to file
            print("Llave simetrica encriptada exitosamente.")

            return key_encrypted
    except Exception as e:
        print("Error técnico." + str(e))   



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
                    print("[-] Apagando servidor")
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

        client.send("SYN".encode(FORMAT))
        respuesta = client.recv(1024).decode(FORMAT)

        print("esta es la resp: " + str(respuesta))
        if respuesta == "ACK":
                client.send(privateKey.encode(FORMAT)) #ojo con el encode pq ya esta en hex
                recv = client.recv(1024).decode(FORMAT)
                if recv == "RECV":
                    client.send(LlaveSim)
                    recv_2 = client.recv(1024).decode(FORMAT)
                    if recv_2 == "RECV SIM":                        
                        print("Envio exitoso doble")
                        client_list.append(client)
                        nicknames.append(nickname)
                else:
                    print("Envio fallido")

        print(chr(27)+'[1;32m',end="")
        print(f"[+] {nickname} ha entrado al chat!")
        broadcast(f"{nickname} ha entrado al chat!\n".encode(FORMAT))
        client.send("Connected to the server.".encode(FORMAT))

        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

privateKey, publicKey = generarParLlaves()
privateKey = encriptarLlavePriv(privateKey, clave_rc4)
#print(privateKey)
LlaveSim = generarLlaveSimetrica()
print("llave simetrica")
print(LlaveSim)
LlaveSim = encriptarLlaveSim(LlaveSim, publicKey)
print("Nueva Llave simetrica")
print(LlaveSim)

def main():
    
      
    server = serverThread()
    server.start()
    receive()

if __name__ == "__main__":
    main()
