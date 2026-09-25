import socket

HOST = "127.0.0.1"
PORT = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((HOST, PORT))

print(f"Servidor escuchando en {HOST}:{PORT}")

while True:
    data, addr = server.recvfrom(1024)

    mensaje = data.decode()

    print(f"Cliente {addr}: {mensaje}")

    respuesta = input("Servidor: ")

    server.sendto(respuesta.encode(), addr)