import socket
import logging
import time

from parser import download_parse_args
from protocolo import HeaderFlags
from lib.channels import ServerChannel
from lib.sack_client import download as download_sack
from lib.saw_client import download as download_saw


def download(server_address, protocol, filename_server, dest_filename):
    logging.getLogger(__name__)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        match protocol:
            case HeaderFlags.Type.SAW:
                channel = ServerChannel(sock, server_address)
                download_saw(channel, filename_server, dest_filename)
            case HeaderFlags.Type.SACK:
                channel = ServerChannel(sock, server_address)
                download_sack(channel, filename_server, dest_filename)
            case _:
                raise ValueError(f"Protocolo {protocol} no implementado.")

    finally:
        sock.close()


def main():
    args = download_parse_args()
    logging.basicConfig(
        level=max(logging.DEBUG, min(
            logging.CRITICAL,
            logging.WARNING + 10 * (args.quiet - args.verbose)
            )),
        format='%(levelname)s: %(message)s',
    )
    logger = logging.getLogger(__name__)
    server_address = (args.host, args.port)
    dest_filename = args.dst if args.dst else args.name
    timer = time.monotonic()
    logger.info(f"Preparando transferencia de {args.name} desde"
                f"{args.host}:{args.port} a {dest_filename}")

    if args.protocol == "stop-and-wait":
        protocol = HeaderFlags.Type.SAW
    elif args.protocol == "sack":
        protocol = HeaderFlags.Type.SACK
    else:
        logger.critical(f"Protocolo incorrecto: {args.protocol}")
        return

    try:
        download(server_address, protocol, args.name, dest_filename)
    except Exception as e:
        logger.critical(f"{e}")
        raise e

    logger.info("Ejecución finalizada")
    print("Tiempo total de transferencia: " +
          f"{time.monotonic() - timer:.2f} segundos")


if __name__ == "__main__":
    main()
