import socket
import os
import logging

from parser import upload_parse_args
from protocolo import (
    ERRORES_DESC, Packet, HeaderFlags,
    MessageSynUpload
)
from lib.channels import Channel, ServerChannel
from lib.saw_client import upload as upload_saw

def upload(server_address, protocol, source_path, dest_filename):
    logging.getLogger(__name__)

    if not os.path.exists(source_path):
        raise IOError(f"El archivo de origen no existe.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        match protocol:
            case HeaderFlags.Type.SAW:
                channel = ServerChannel(sock, server_address)
                upload_saw(channel, source_path, dest_filename)
            case HeaderFlags.Type.SACK:
                raise NotImplementedError("Protocolo SACK no implementado.")
            case _:
                raise ValueError(f"Protocolo {protocol} no implementado.")

    finally:
        sock.close()

def main():
    args = upload_parse_args()
    logging.basicConfig(
        level=max(logging.DEBUG, min(logging.CRITICAL, logging.WARNING + 10 * (args.quiet - args.verbose))),
        format='%(levelname)s: %(message)s',
    )
    logger = logging.getLogger(__name__)
    logger.info(f"Preparando transferencia de {args.src} a {args.host}:{args.port}")
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