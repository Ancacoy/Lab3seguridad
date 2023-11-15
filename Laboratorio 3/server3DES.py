import socket
import random
from Crypto.Cipher import DES3
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
    s.bind((HOST, PORT))
    s.listen()
    print("Esperando conexión...")
    conn, addr = s.accept()
    with conn:
        print(f"Conectado a {addr}")

        # Paso de Diffie-Hellman
        server_private_key, server_public_key = diffie_hellman(p, g)
        conn.send(str(server_public_key).encode())
        client_public_key = int(conn.recv(1024).decode())
        shared_key = calculate_shared_key(server_private_key, client_public_key, p)

        # Desencriptar mensaje
        with open('mensajerecibido1.txt', 'wb') as file:
            encrypted_message = conn.recv(1024)
            hashed_key = hashlib.sha256(str(shared_key).encode()).digest()[:24]  # Clave para 3DES
            cipher = DES3.new(hashed_key, DES3.MODE_ECB)
            decrypted_message = cipher.decrypt(encrypted_message)
            file.write(decrypted_message.rstrip(b' '))  # Quitar espacios de relleno
        print("Mensaje desencriptado guardado en mensajerecibido.txt")
