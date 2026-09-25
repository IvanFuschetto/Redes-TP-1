import socket

HOST = "127.0.0.1"
PORT = 5000

def desformatear_de_protocolo(data: bytes):
    """
    Desempaqueta la cabecera personalizada de 12 bytes y extrae el payload.
    """
    seq_num = int.from_bytes(data[0:4], byteorder="big")
    ack_num = int.from_bytes(data[4:8], byteorder="big")
    version = int.from_bytes(data[8:9], byteorder="big")
    flags = int.from_bytes(data[9:10], byteorder="big")
    ack_protocol = int.from_bytes(data[10:12], byteorder="big")

    payload = data[HEADER_SIZE:]

    return seq_num, ack_num, version, flags, ack_protocol, payload

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((HOST, PORT))

print(f"Servidor escuchando en {HOST}:{PORT}")

while True:
    data, addr = server.recvfrom(1024)

    mensaje = data.decode()

    print(f"Cliente {addr}: {mensaje}")

    respuesta = input("Servidor: ")

    server.sendto(respuesta.encode(), addr)