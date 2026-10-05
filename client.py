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
    MTU,
    build_flags,
    parse_flags,
    make_packet,
    parse_packet,
    ERR_NONE,
    ERRORES_DESC, Packet, HeaderFlags,
    MessageSynUpload
)
from lib.channels import ServerChannel
from lib.sack_client import upload as upload_sack





SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000
 

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
            sequence_number = sequence_number if sequence_number < 256 else sequence_number - 256
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
                print("SACK")
                upload_sack(ServerChannel(sock, server_address), source_path, dest_filename)
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

if __name__ == "__main__":
    main()

