# Felipe Vera y Marcelo Ibarra, Seguridad Informática

import socket
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

def llave_8bytes(number):
    # Convertir el número a una cadena de bytes
    number_bytes = str(number).encode('utf-8')

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

    # Tomar los primeros 8 bytes como clave DES
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

def desencriptar_mensaje_DES(mensaje_ecriptado, llave):
    llave= llave_8bytes(llave)
    cipher = DES.new(llave, DES.MODE_ECB)
    mensaje_desencriptado = cipher.decrypt(mensaje_ecriptado)
    mensaje_despadeado = unpad(mensaje_desencriptado, DES.block_size)
    return mensaje_despadeado.decode('utf-8')

def desencriptar_mensaje_3DES(mensaje_ecriptado, llave):
    llave= llave_24bytes(llave)
    cipher = DES3.new(llave, DES3.MODE_ECB)
    mensaje_desencriptado = cipher.decrypt(mensaje_ecriptado)
    mensaje_despadeado = unpad(mensaje_desencriptado, DES3.block_size)
    return mensaje_despadeado.decode('utf-8')

def desencriptar_mensaje_AES(mensaje_ecriptado, llave, iv):
    llave= llave_16bytes(llave)
    cipher = AES.new(llave, AES.MODE_CBC, iv)
    mensaje_desencriptado = cipher.decrypt(mensaje_ecriptado)
    mensaje_despadeado = unpad(mensaje_desencriptado, AES.block_size)
    return mensaje_despadeado.decode('utf-8')

# Configuración del cliente
host = '127.0.0.1'
port = 12345

# Crear un socket del cliente
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Conectar al servidor
client_socket.connect((host, port))



######### Este es el ciclo infinito donde se pueden implementar todas las cosas del lab ###########

while True:


    # Recibir mensaje del servidor, tambien lo muestra en pantalla
    response = client_socket.recv(1024).decode()
    print(f"Respuesta del servidor: {response}")


    # Enviar mensaje al servidor, funciona igual que en codigo del server
    message = input("Mensaje al servidor: ")
    client_socket.send(message.encode())

    if message == "1":

        ################### Diffie Hellman ###################################
        
        p = 23
        g = 5
        b = 15
        B = g**b%p

        # Paso 2: recibe la llave del servidor
        llave_publica = int(client_socket.recv(1024).decode())

        # Paso 3: envía su llave pública al servidor
        client_socket.send(str(B).encode())

        clave_secreta = (llave_publica**b)%p

        print("\n\nClave secreta: ", clave_secreta,"\n\n")

        #paso 7: desencriptar
        mensaje_encriptado= client_socket.recv(1024)
        

        mensaje_desencriptado = desencriptar_mensaje_DES(mensaje_encriptado, clave_secreta)
 
        
        #paso 8: crear archivo y guardar mensaje
        seguro = open("mensajeseguro.txt",'a')
        seguro.write(mensaje_desencriptado)
        seguro.close()

    elif message == "2":
        #repetir paso 1 al 4
        ################### Diffie Hellman ###################################
        
        p = 23
        g = 5
        b = 15
        B = g**b%p

        # Paso 2: recibe la llave del servidor
        llave_publica = int(client_socket.recv(1024).decode())

        # Paso 3: envía su llave pública al servidor
        client_socket.send(str(B).encode())

        clave_secreta = (llave_publica**b)%p

        print("\n\nClave secreta: ", clave_secreta,"\n\n")

        #paso 7: desencriptar
        mensaje_encriptado= client_socket.recv(1024)
        
        mensaje_desencriptado = desencriptar_mensaje_3DES(mensaje_encriptado, clave_secreta)
 
        
        #paso 8: crear archivo y guardar mensaje
        seguro = open("mensajeseguro.txt",'a')
        seguro.write(mensaje_desencriptado)
        seguro.close()
        

    elif message == "3":
        #repetir paso 1 al 4
        ################### Diffie Hellman ###################################
        
        p = 23
        g = 5
        b = 15
        B = g**b%p

        # Paso 2: recibe la llave del servidor
        llave_publica = int(client_socket.recv(1024).decode())

        # Paso 3: envía su llave pública al servidor
        client_socket.send(str(B).encode())

        clave_secreta = (llave_publica**b)%p

        print("\n\nClave secreta: ", clave_secreta,"\n\n")

        #paso 7: desencriptar
        mensaje_encriptado= client_socket.recv(1024)
        client_socket.send('Recivido'.encode())
        iv= client_socket.recv(1024)

        mensaje_desencriptado = desencriptar_mensaje_AES(mensaje_encriptado, clave_secreta, iv)

        #paso 8: crear archivo y guardar mensaje
        seguro = open("mensajeseguro.txt",'a')
        seguro.write(mensaje_desencriptado)
        seguro.close()
        ######################################################################

        

        

    
    
    


    


##########################################################################################################
    

#Cerrar la conexión (Esta parte del codigo en realidad nunca se ejecuta,
#pero sería una buena practica cerrar los socket luego de terminar todos los procesos

client_socket.close()


