import socket
import os
import time
from enum import Enum


HOST = "127.0.0.1"
PORT = 5000

#class Flags(Enum):
#    SYN = 1
#    ACK = 2
#    FIN = 3
    #SYN_ACK = 3



from protocolo import (
    HEADER_SIZE,
    MAX_PAYLOAD,
    build_flags,
    parse_flags,
    make_packet,
    parse_packet,
    ERR_NONE,
    ERRORES_DESC,
)

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000


def synchronize_with_server(sock_client,syn_pkt,server_addr):
    rtt_muestra = 1
    rtt_estimado = 1
    rtt_desviacion = 1
    #rtt_estimado = 0.875*rtt_estimado + 0.125*rtt_muestra
    #rtt_desviacion = 0.75*rtt_desviacion + 0.25*abs(rtt_muestra - rtt_estimado)
    #timeout = rtt_estimado + 4*rtt_desviacion
    contador = 0
    timeout = 1
    while contador <5:
        
        sock_client.settimeout(timeout)
        inicio = time.perf_counter()
        
        sock_client.sendto(syn_pkt, server_addr)
        
        #Recepcion acksyn --> ack + syn = acksyn
        #falta checkear si es ack.y syn
        #sock_client.settimeout(timeout)
        try:
            data, _ = sock_client.recvfrom(HEADER_SIZE + MAX_PAYLOAD)

            fin = time.perf_counter()
            
            rtt_muestra = fin - inicio

            rtt_estimado= 0.875*rtt_estimado + 0.125*rtt_muestra
            rtt_desviacion = 0.75*rtt_desviacion + 0.25*abs(rtt_muestra - rtt_estimado)
            timeout = rtt_estimado + 4*rtt_desviacion
            
            _, _, flags_byte, _ = parse_packet(data)
            info = parse_flags(flags_byte)
            
            if info["error"] != ERR_NONE:
                print(f"El servidor rechazo el upload: {ERRORES_DESC[info['error']]}")
                return
            print("Servidor acepto el upload, comenzando transferencia...")
            break
        except:
            contador += 1
            timeout *= 2
            continue
 



def upload(ruta_local):

    #Abrir socket UDP
    sock_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (SERVER_HOST, SERVER_PORT)


    #verificacion de existencia del archivo local
    if not os.path.exists(ruta_local):
        print("El archivo local no existe.")
        return
    
    tamanio_archivo = os.path.getsize(ruta_local)
    nombre_archivo = os.path.basename(ruta_local)
 
    # SYN: pido iniciar un upload, mando el nombre de archivo en el payload

        #Se arman las flags 
    flags = build_flags(updown=1, syn=1,ack=0,fin=0,error=ERR_NONE)
        #Se arma el payload
    payload = tamanio_archivo.to_bytes(3, byteorder="big") + len(nombre_archivo).to_bytes(1, byteorder="big") +  nombre_archivo.encode() 
        #Se arma el paquete SYN
    syn_pkt = make_packet(0, 0, flags, payload)

        #Tendria que ser un bucle

    synchronize_with_server(sock_client,syn_pkt,server_addr)
 
    seq = 0
    with open(ruta_local, "rb") as f:
        while True:
            chunk = f.read(MAX_PAYLOAD)
 
            if not chunk:
                fin_pkt = make_packet(seq, 0, build_flags(fin=1))
                sock_client.sendto(fin_pkt, server_addr)
                data, _ = sock_client.recvfrom(HEADER_SIZE)
                _, _ack_num, flags_byte, _ = parse_packet(data)
                info = parse_flags(flags_byte)
                if info["ack"] and info["fin"]:
                    print("Upload finalizado con exito.")
                return
 
            pkt = make_packet(seq, 0, build_flags(), chunk)
            sock_client.sendto(pkt, server_addr)
 
            data, _ = sock_client.recvfrom(HEADER_SIZE + MAX_PAYLOAD)
            _, r_ack, r_flags_byte, _ = parse_packet(data)
            info = parse_flags(r_flags_byte)
 
            if info["ack"] and r_ack == seq:
                seq = 1 - seq
            else:
                print("ACK inesperado (todavia sin retransmision).")
 



def main():

    #sock_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #server_addr = (SERVER_HOST, SERVER_PORT)

    operation = input("Que operacion queres hacer? (upload/download): ").strip().lower()

    if operation == "upload":
        ruta = input("Ruta del archivo local a subir: ").strip()
        upload(ruta)
    elif operation == "download":
        nombre = input("Nombre del archivo a descargar: ").strip()
        hacer_download(sock, server_addr, nombre)
    else:
        print("Operacion invalida. Usa 'upload' o 'download'.")

    #sock_client.close()

main()

"""
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
"""