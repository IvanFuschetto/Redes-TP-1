import socket
import os
import time
from enum import Enum

import logging
from parser import upload_parse_args

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
    ERRORES_DESC, Packet, HeaderFlags,
    MessageSynUpload
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




def _upload(ruta_local):

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
 



# def main():
#
#     #sock_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     #server_addr = (SERVER_HOST, SERVER_PORT)
#
#     operation = input("Que operacion queres hacer? (upload/download): ").strip().lower()
#
#     if operation == "upload":
#         ruta = input("Ruta del archivo local a subir: ").strip()
#         upload(ruta)
#     elif operation == "download":
#         nombre = input("Nombre del archivo a descargar: ").strip()
#         hacer_download(sock, server_addr, nombre)
#     else:
#         print("Operacion invalida. Usa 'upload' o 'download'.")
#
#     #sock_client.close()

def upload_stop_and_wait(sock, server_address, source_path, dest_filename):
    sequence_number = 1
    ### Start SYN
    packet = Packet(
        sequence_number=sequence_number,
        ack_number=0,
        flags=HeaderFlags(
            type=HeaderFlags.Type.SAW,
            operation=HeaderFlags.Operation.UPLOAD,
            ack=False, syn=True, fin=False,
        ),
        payload=MessageSynUpload(
            file_size=os.path.getsize(source_path),
            file_name=dest_filename,
        ).serialize()
    )
    respuesta = try_send(sock, server_address, packet)
    if respuesta.header.flags.error:
        logging.error(f"({respuesta.header.flags.error}) {ERRORES_DESC[respuesta.header.flags.error]}")
        return

    with open(source_path, "rb") as f:
        while True:
            sequence_number += 1
            chunk = f.read(MAX_PAYLOAD)
            if not chunk:
                break

            packet = Packet(
                sequence_number=sequence_number,
                ack_number=0,
                flags=HeaderFlags(
                    type=HeaderFlags.Type.SAW,
                    operation=HeaderFlags.Operation.UPLOAD,
                    ack=False, syn=False, fin=False,
                ),
                payload=chunk
            )
            respuesta = try_send(sock, server_address, packet)
            if respuesta.header.flags.error:
                logging.error(f"({respuesta.header.flags.error}) {ERRORES_DESC[respuesta.header.flags.error]}")
                return

    # Send FIN
    packet = Packet(
        sequence_number=sequence_number,
        ack_number=0,
        flags=HeaderFlags(
            type=HeaderFlags.Type.SAW,
            operation=HeaderFlags.Operation.UPLOAD,
            ack=False, syn=False, fin=True,
        )
    )
    respuesta = try_send(sock, server_address, packet)
    if respuesta.header.flags.error:
        logging.error(f"({respuesta.header.flags.error}) {ERRORES_DESC[respuesta.header.flags.error]}")
        return

def upload(server_address, protocol, source_path, dest_filename):
    logging.getLogger(__name__)

    if not os.path.exists(source_path):
        raise IOError(f"El archivo de origen no existe.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        match protocol:
            case HeaderFlags.Type.SAW:
                upload_stop_and_wait(sock, server_address, source_path, dest_filename)
            case HeaderFlags.Type.SACK:
                raise NotImplementedError("Protocolo SACK no implementado.")
            case _:
                raise ValueError(f"Protocolo {protocol} no implementado.")
    except Exception as e:
        sock.close()
        raise e


def try_send(sock, address, packet: Packet) -> Packet:
    """
    Intenta y reintenta enviar el `packet` a través de `sock` a `address`.
    Devuelve el Packet recibido.
    """

    timeout = 1
    sock.settimeout(timeout)

    timeout_cont = 0
    while timeout_cont < 5:
        try:
            ack_number_esperado = packet.header.sequence_number
            sock.sendto(packet.serialize(), address)
            logging.debug(f"Enviando {packet}")

            while True:
                respuesta_bytes, _ = sock.recvfrom(HEADER_SIZE + MAX_PAYLOAD)
                respuesta = Packet.deserialize(respuesta_bytes)
                logging.debug(f"Recibido {respuesta}")

                if respuesta.header.flags.ack and respuesta.header.ack_number == ack_number_esperado:
                    return respuesta

        except socket.timeout:
            logging.debug(f"Timeout {packet}")
            timeout_cont += 1
            timeout *= 2
            sock.settimeout(timeout)
            continue

    raise TimeoutError("Error de Conexión ! Demasiados Timeouts")



def main():
    args = upload_parse_args()
    logging.basicConfig(
        level=max(logging.DEBUG, min(logging.CRITICAL, logging.WARNING + 10 * (args.quiet - args.verbose))),
        format='%(levelname)s: %(message)s',
    )
    logger = logging.getLogger(__name__)
    #logger.debug(f"Preparando transferencia de {args.src} a {args.host}:{args.port}")
    logger.info(f"Preparando transferencia de {args.src} a {args.host}:{args.port}")
    #logger.warning(f"Preparando transferencia de {args.src} a {args.host}:{args.port}")
    server_address = (args.host, args.port)
    dest_filename = args.name if args.name else os.path.basename(args.src)
    logger.info(f"Filename: {dest_filename}")

    if args.protocol == "stop-and-wait":
        protocol = HeaderFlags.Type.SAW
    elif args.protocol == "sack":
        protocol = HeaderFlags.Type.SACK
    else:
        logger.critical(f"Protocolo incorrecto: {args.protocol}")
        return

    try:
        upload(server_address, protocol, args.src, dest_filename)
    except Exception as e:
        logger.critical(f"{e}")

    logger.info(f"Ejecución finalizada")

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