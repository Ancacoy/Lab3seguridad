import socket
import random
from Crypto.Cipher import DES
import hashlib

HOST = 'localhost'  # Dirección del servidor
PUERTO = 65432  # Puerto de escucha
p = 23  # Número primo compartido para Diffie-Hellman
g = 5  # Generador para Diffie-Hellman

# Función para generar la clave privada y la clave pública en el intercambio de Diffie-Hellman
def diffie_hellman(p, g):
    clave_privada = random.randint(1, p - 1)  # Genera una clave privada aleatoria
    clave_publica = (g ** clave_privada) % p  # Calcula la clave pública correspondiente
    return clave_privada, clave_publica

# Función para calcular la clave compartida usando la clave privada y la clave pública
def calcular_clave_compartida(clave_privada, clave_publica, p):
    return (clave_publica ** clave_privada) % p  # Calcula la clave compartida

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PUERTO))  # Enlaza el socket al host y puerto especificados
    s.listen()  # Escucha las conexiones entrantes
    print("Esperando conexión...")
    conexion, direccion = s.accept()  # Acepta la conexión entrante
    with conexion:
        print(f"Conectado a {direccion}")

        # Intercambio de claves Diffie-Hellman
        clave_privada_servidor, clave_publica_servidor = diffie_hellman(p, g)  # Claves del servidor
        conexion.send(str(clave_publica_servidor).encode())  # Envía la clave pública al cliente
        clave_publica_cliente = int(conexion.recv(1024).decode())  # Recibe la clave pública del cliente
        clave_compartida = calcular_clave_compartida(clave_privada_servidor, clave_publica_cliente, p)  # Calcula la clave compartida

        # Desencriptar mensaje recibido
        with open('mensajerecibido.txt', 'wb') as archivo:
            mensaje_cifrado = conexion.recv(1024)  # Recibe el mensaje cifrado
            # Genera una clave a partir de la clave compartida  la convierte a una cadena de texto y la codifica a bytes 
            clave_hasheada = hashlib.sha256(str(clave_compartida).encode()).digest()[:8] #64bits  
            cifrador = DES.new(clave_hasheada, DES.MODE_ECB)  #  utiliza la biblioteca DES y la clave hasehada para crear un cifrado DES
            mensaje_descifrado = cifrador.decrypt(mensaje_cifrado)  # Descifra el mensaje
            archivo.write(mensaje_descifrado.rstrip(b' '))  # Escribe el mensaje descifrado en un archivo
        print("Mensaje desencriptado guardado en mensajerecibido.txt")

