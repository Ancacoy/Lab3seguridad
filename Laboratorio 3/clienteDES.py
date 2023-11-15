import socket
import random
from Crypto.Cipher import DES
import hashlib

# Función para el intercambio de claves de Diffie-Hellman
def intercambio_diffie_hellman(p, g):
    clave_privada = random.randint(1, p - 1)  # Clave privada generada aleatoriamente para el cliente
    clave_publica = (g ** clave_privada) % p  # Cálculo de clave pública del cliente
    return clave_privada, clave_publica

# Función para calcular la clave compartida
def calcular_clave_compartida(clave_privada, clave_publica, p):
    return (clave_publica ** clave_privada) % p  # Cálculo de la clave compartida

# Dirección y puerto del servidor
DIRECCION = 'localhost'  # Dirección IP del servidor
PUERTO = 65432  # Número de puerto del servidor

# Parámetros para Diffie-Hellman
p = 23  # Número primo compartido
g = 5  # Generador para el grupo

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conexion:
    conexion.connect((DIRECCION, PUERTO))  # Establecer conexión con el servidor

    # Paso de Diffie-Hellman
    clave_privada_cliente, clave_publica_cliente = intercambio_diffie_hellman(p, g)
    conexion.send(str(clave_publica_cliente).encode())  # Enviar clave pública del cliente al servidor
    clave_publica_servidor = int(conexion.recv(1024).decode())  # Recibir clave pública del servidor
    clave_compartida = calcular_clave_compartida(clave_privada_cliente, clave_publica_servidor, p)  # Calcular clave compartida

    # Encriptar mensaje y enviar al servidor
    with open('mensajeentrada.txt', 'rb') as archivo:
        mensaje = archivo.read()  # Leer el contenido del archivo
        while len(mensaje) % 8 != 0:
            mensaje += b' '  # Rellenar el mensaje para que sea múltiplo de 8 bytes

        # Crear una clave a partir de la clave compartida mediante hash SHA256 y truncar a 8 bytes (64 bits)
        clave_hasheada = hashlib.sha256(str(clave_compartida).encode()).digest()[:8]
        # Crear un objeto de cifrado DES en modo ECB (Electronic Codebook)
        cifrador = DES.new(clave_hasheada, DES.MODE_ECB)
        # Encriptar el mensaje utilizando DES
        mensaje_encriptado = cifrador.encrypt(mensaje)
        # Imprimir el mensaje encriptado en formato hexadecimal
        print("Mensaje cifrado en hexadecimal:", mensaje_encriptado.hex())
        # Enviar el mensaje encriptado al servidor
        conexion.send(mensaje_encriptado)
        
    print("Mensaje encriptado y enviado al servidor")
