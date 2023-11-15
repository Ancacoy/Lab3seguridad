import socket
import random
from Crypto.Cipher import AES
import hashlib
def diffie_hellman(p, g):
    private_key = random.randint(1, p - 1)
    public_key = (g ** private_key) % p
    return private_key, public_key

def calculate_shared_key(private_key, public_key, p):
    return (public_key ** private_key) % p

HOST = 'localhost'
PORT = 65432
p = 23
g = 5

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Paso de Diffie-Hellman
    client_private_key, client_public_key = diffie_hellman(p, g)
    s.send(str(client_public_key).encode())
    server_public_key = int(s.recv(1024).decode())
    shared_key = calculate_shared_key(client_private_key, server_public_key, p)

    # Encriptar mensaje y enviar al servidor
    with open('mensajeentrada.txt', 'rb') as file:
        message = file.read()
        # Rellenar el mensaje para que sea múltiplo de 16 bytes (bloque de AES)
        while len(message) % 16 != 0:
            message += b' '  # Relleno con espacios

        hashed_key = hashlib.sha256(str(shared_key).encode()).digest()[:16]  # Clave para AES (16 bytes)
        cipher = AES.new(hashed_key, AES.MODE_ECB)
        encrypted_message = cipher.encrypt(message)
            
        # Imprimir el mensaje cifrado en hexadecimal
        print("Mensaje cifrado en hexadecimal:", encrypted_message.hex())

        s.send(encrypted_message)
    print("Mensaje encriptado y enviado al servidor")
