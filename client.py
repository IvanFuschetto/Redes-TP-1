import socket

HOST = "127.0.0.1"
PORT = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    #mensaje = input("Cliente: ")
    mensaje = 45
    mensaje = bytes([mensaje]) + b"Hola, servidor!"

    client.sendto(mensaje.encode(), (HOST, PORT))

    data, addr = client.recvfrom(1024)

    respuesta = data.decode()

    print(f"Servidor: {respuesta}")