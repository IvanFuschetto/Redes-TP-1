import socket
from enum import Enum

VERSION = 1
HOST = "127.0.0.1"
PORT = 5000

class Flags(Enum):
    #SYN = 1
    ACK = 2
    FIN = 3
    #SYN_ACK = 3


def formatear_a_protocolo(seq_number: int,ack_number: int,valor_flag:Flags, ack_protocol: int ,payload: bytes) -> bytes:
    # Conversión binaria
    b_seq = seq_number.to_bytes(4, byteorder="big")
    b_ack = ack_number.to_bytes(4, byteorder="big")
    b_ver = VERSION.to_bytes(1, byteorder="big")
    b_flags = valor_flag.value.to_bytes(1, byteorder="big")
    b_ack_proto = ack_protocol.to_bytes(2, byteorder="big")

    # Armado de la cabecera (11 bytes en total)
    header = b_seq + b_ack + b_ver + b_flags + b_ack_proto

    return header + payload


def send_file(file_path: str, client: socket.socket):
    with open(file_path, 'rb') as file:
        while True:
            chunk = file.read(1024)
            if not chunk:
                break
            client.sendto(chunk, (HOST, PORT))


def main():

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    syn = Flags.ACK
    print(type(syn))
    print(syn.value)
    print(type(syn.value))

    while True:
        mensaje = input("Cliente: ")
        #mensaje = 45
        mensaje = bytes([mensaje]) + b"Hola, servidor!"

        client.sendto(mensaje.encode(), (HOST, PORT))

        data, addr = client.recvfrom(1024)

        respuesta = data.decode()

        print(f"Servidor: {respuesta}")


main()