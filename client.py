import socket
import threading
import time
import sys
import os
import numpy as np
import cryptography
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

try:
    HEADER = 64
    PORT = 5050
    FORMAT = 'utf-8'
    DISCONNECT_MESSAGE = "!DISCONNECT"
    SERVER = "127.0.0.1"
    ADDR = (SERVER,PORT)
    LlavePrivada = None
    LlaveSim = None
    nickname = ""
    clave_rc4 = "elfinalito" #Clave de prueba
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
            #msg = encriptarMsg(msg,LlaveSim)
            data = f"$ {nickname}: {msg}"
            client.send(data.encode(FORMAT))

def receive():
    while True:
        try:
            msg = client.recv(2048).decode(FORMAT)

            if msg == "Nickname?: ":
                client.send(nickname.encode(FORMAT))
                
            elif msg == "SYN":
                client.send("ACK".encode(FORMAT))
                try:
                    LlavePrivada = client.recv(2048)
                    client.send("RECV".encode(FORMAT))
                    LlaveSim = client.recv(2048)
                    if LlaveSim is not None:
                        client.send("RECV SIM".encode(FORMAT))
                        print(LlaveSim)
                    #print(LlavePrivada)
                    LlavePrivada = desencriptarLlavePriv(LlavePrivada,clave_rc4)
                    LlaveSim = desencriptarLlaveSimetrica(LlaveSim,LlavePrivada)
                    print(LlaveSim)
                except:
                    print("Error en el intercambio")
            else:
                #msg = desencriptarMsg(msg,LlaveSim)
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
def desencriptarLlavePriv(LlavePriv, ClaveRC):
  
    llave = llave_to_array(ClaveRC)

    S = KSA(llave)
    cadena_cifrante = np.array(PRGA(S, len(LlavePriv)//2))
    print("\nKeystream:")
    print(cadena_cifrante)

    hex_list = [LlavePriv[i:i+2] for i in range(0, len(LlavePriv), 2)]
    texto2 = np.array([int(i,16) for i in hex_list])

    NuevaLlavePriv = cadena_cifrante ^ texto2

    print("\nLlave privada en Hexadecimal:")
    print(LlavePriv) #imprime en hexadecimal
    print("\nUnicode:")
    NuevaLlavePriv = "".join([chr(c) for c in NuevaLlavePriv])
    print("nueva llave priv desencriptada")
    print(NuevaLlavePriv)

    return NuevaLlavePriv
def desencriptarLlaveSimetrica(LlaveSimetricaEnc, LlavePrivada):
    try:
        # Private RSA key
        private_key = RSA.import_key(LlavePrivada)
        # Private decrypter
        private_crypter = PKCS1_OAEP.new(private_key)
        # Decrypted session key
        LlaveSimetricaDes = private_crypter.decrypt(LlaveSimetricaEnc)
        print('Llave simetrica desencriptada exitosamente!')
        return LlaveSimetricaDes
    except ValueError as e:
        print("Error Tecnico: " + str(e))
def calcHash(msg): #solo prueba
    msgHashed = "//HASH"
    return msgHashed
def encriptarMsg(msg, LlaveSimetrica): #solo prueba
    msgHash = calcHash(msg)
    newMsg = msg + msgHash
    fernet = Fernet(LlaveSimetrica)
    newMsg = str.encode(msgHash)
    encrypted = fernet.encrypt(newMsg)
    return encrypted
def desencriptarMsg(msg, LlaveSimetrica): #solo prueba
    fernet = Fernet(LlaveSimetrica)
    decrypted = fernet.decrypt(str.encode(msg))
    newMsg = decrypted.rsplit("//",-1)
        
    return newMsg


def main():
    thread_recieve = threading.Thread(target=receive)
    thread_write = threading.Thread(target=write)

    thread_recieve.start()
    thread_write.start()

if __name__ == "__main__":
    nickname = input("Ingrese su nombre de usuario: ")
    main()
