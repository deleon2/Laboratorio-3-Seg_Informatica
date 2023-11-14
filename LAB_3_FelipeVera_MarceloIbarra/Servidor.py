# Felipe Vera y Marcelo Ibarra, Seguridad Informática
import socket
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
################### Manejo TXT ############################################################

# Accede al archivo de texto inicial en modo lectura
entrada = open("mensajedeentrada.txt",'r')

# Toma el contenido del archivo de texto y lo guarda dentro de la variable mensaje
mensaje = ""
for texto in entrada:
    mensaje = mensaje+texto

###########################Funciones#####################################################
def llave_8bytes(numero):
    # Convertir el número a una cadena de bytes
    number_bytes = str(numero).encode('utf-8')

    # Usar SHA-256 para obtener una clave de 32 bytes
    hash_object = SHA256.new(data=number_bytes)
    hash_bytes = hash_object.digest()

    # Tomar los primeros 8 bytes como clave DES
    key_des = hash_bytes[:8]
    return key_des


def llave_24bytes(numero):
    # Convertir el número a una cadena de bytes
    number_bytes = str(numero).encode('utf-8')

    # Usar SHA-256 para obtener una clave de 32 bytes
    hash_object = SHA256.new(data=number_bytes)
    hash_bytes = hash_object.digest()

    # Tomar los primeros 24 bytes como clave DES
    key_des = hash_bytes[:24]
    return key_des

def llave_16bytes(numero):
    # Convertir el número a una cadena de bytes
    number_bytes = str(numero).encode('utf-8')

    # Usar SHA-256 para obtener una clave de 32 bytes
    hash_object = SHA256.new(data=number_bytes)
    hash_bytes = hash_object.digest()

    # Tomar los primeros 16 bytes como clave DES
    key_des = hash_bytes[:16]
    return key_des

def encriptar_mensaje_DES(mensaje, llave):
    llave= llave_8bytes(llave)
    cipher = DES.new(llave, DES.MODE_ECB)
    mensaje_padeado = pad(mensaje.encode('utf-8'),DES.block_size)
    mensaje_encriptado = cipher.encrypt(mensaje_padeado)
    return mensaje_encriptado

def encriptar_mensaje_3DES(mensaje, llave):
    llave= llave_24bytes(llave)
    cipher = DES3.new(llave, DES3.MODE_ECB)
    mensaje_padeado = pad(mensaje.encode('utf-8'), DES3.block_size)
    mensaje_encriptado = cipher.encrypt(mensaje_padeado)
    return mensaje_encriptado

def encriptar_mensaje_AES(mensaje, llave):
    llave= llave_16bytes(llave)
    cipher = AES.new(llave, AES.MODE_CBC)
    mensaje_padeado = pad(mensaje.encode('utf-8'), AES.block_size)
    mensaje_encriptado = cipher.encrypt(mensaje_padeado)
    return mensaje_encriptado, cipher.iv

############# Configuración del servidor ###########################################################################

# Configuración del servidor
host = '127.0.0.1'
port = 12345

# Crear un socket del servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Vincular el socket al host y puerto especificados
server_socket.bind((host, port))

# Escuchar conexiones entrantes (máximo 1 en este caso)
server_socket.listen(1)

print(f"El servidor está esperando conexiones en {host}:{port}...")

# Aceptar la conexión entrante
client_socket, client_address = server_socket.accept()
print(f"Conexión establecida con {client_address}")


# En response va lo que se le quiere enviar al cliente
response = "¿Con qué acción te gustaría trabajar?:\n1.- Encriptado DES\n2.- Encriptado 3DES\n3.- Encriptado AES"
# Esta es la linea de codigo que envía los mensaje, dentro del ciclo tambien está definida
client_socket.send(response.encode())
##################################################################################################################

############## Este es el ciclo infinito donde se pueden implementar todas las cosas del lab ###########

while True:
    
    # Recibir mensaje del cliente, llegan en formato de string
    message = client_socket.recv(1024).decode()

    if message == "1":

        ######################### Diffie Hellman ###########################
        p = 23
        g = 5
        a = 6
        A = g**a%p

        # Paso 1: envía su llave púbica al cliente
        client_socket.send(str(A).encode())

        # Paso 4: recibe la llave pública del cliente
        llave_publica = int(client_socket.recv(1024).decode())

        clave_secreta = (llave_publica**a)%p

        print("\n\nClave secreta: ", clave_secreta,"\n\n")

        #paso 5: encriptar
        mensaje_encriptado = encriptar_mensaje_DES(mensaje, clave_secreta)
        print(mensaje_encriptado)
        
        #paso 6: enviar encriptado
        client_socket.send(mensaje_encriptado)

        ####################################################################

    elif message == "2":

        #repetir paso 1 al 4
        ######################### Diffie Hellman ###########################
        p = 23
        g = 5
        a = 6
        A = g**a%p

        # Paso 1: envía su llave púbica al cliente
        client_socket.send(str(A).encode())

        # Paso 4: recibe la llave pública del cliente
        llave_publica = int(client_socket.recv(1024).decode())

        clave_secreta = (llave_publica**a)%p

        print("\n\nClave secreta: ", clave_secreta,"\n\n")

        #paso 5
        mensaje_encriptado = encriptar_mensaje_3DES(mensaje, clave_secreta)
        print(mensaje_encriptado)
        
        #paso 6: enviar encriptado
        client_socket.send(mensaje_encriptado)

        

    elif message == "3":
        
        #repetir paso 1 al 4
        ######################### Diffie Hellman ###########################
        p = 23
        g = 5
        a = 6
        A = g**a%p

        # Paso 1: envía su llave púbica al cliente
        client_socket.send(str(A).encode())

         # Paso 4: recibe la llave pública del cliente
        llave_publica = int(client_socket.recv(1024).decode())

        clave_secreta = (llave_publica**a)%p

        print("\n\nClave secreta: ", clave_secreta,"\n\n")

        #paso 5
        mensaje_encriptado, iv = encriptar_mensaje_AES(mensaje, clave_secreta)
        print(mensaje_encriptado)
        
        #paso 6: enviar encriptado
        client_socket.send(mensaje_encriptado)
        client_socket.recv(1024).decode()
        client_socket.send(iv)

        
        

##########################################################################################################  



#Cerrar la conexión (Esta parte del codigo en realidad nunca se ejecuta,
#pero sería una buena practica cerrar los socket luego de terminar todos los procesos

client_socket.close()
server_socket.close()
