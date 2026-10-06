import logging
import socket
import threading
from queue import Queue

from parser import server_parse_args
from protocolo import Packet, MessageSynUpload, HeaderFlags, ERRORES_DESC, MTU, MAX_PACKET_SIZE
from lib.channels import ClientChannel
from lib.validators import validar_upload
from lib.sack_server import upload_client_handler as upload_sack_client_handler
from lib.sack_server import download_client_handler as download_sack_client_handler
from lib.saw_server import upload_client_handler as upload_saw_client_handler
from lib.saw_server import download_client_handler as download_saw_client_handler

def main():
    args = server_parse_args()
    logging.basicConfig(
        level=max(logging.DEBUG, min(logging.CRITICAL, logging.WARNING + 10 * (args.quiet - args.verbose))),
        format='%(levelname)s: %(message)s',
    )
    logger = logging.getLogger(__name__)
    logger.debug(f"Almacenando en {args.storage}")
    logger.info(f"Servidor escuchando en {args.host}:{args.port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))

    # Cada 5 segundos, el socket lanza un timeout para poder inyectar el KeyboardInterrupt
    sock.settimeout(5)

    conexiones = {}

    stop_event = threading.Event()

    try:
        while True:
            clean_conexiones(conexiones)
            try:
                packet_bytes, address = sock.recvfrom(MAX_PACKET_SIZE)
                packet = Packet.deserialize(packet_bytes)

                if not address in conexiones:
                    if packet.header.flags.syn:
                        logger.info(f"Creando conexión para {address}")
                        queue = Queue()
                        if packet.header.flags.type == HeaderFlags.Type.SAW and packet.header.flags.operation == HeaderFlags.Operation.UPLOAD:
                            channel = ClientChannel(sock, queue, address)
                            thread = threading.Thread(target=upload_saw_client_handler, args=(channel, args.storage, stop_event))
                        elif packet.header.flags.type == HeaderFlags.Type.SAW and packet.header.flags.operation == HeaderFlags.Operation.DOWNLOAD:
                            channel = ClientChannel(sock, queue, address)
                            thread = threading.Thread(target=download_saw_client_handler, args=(channel, args.storage, stop_event))
                        elif packet.header.flags.type == HeaderFlags.Type.SACK and packet.header.flags.operation == HeaderFlags.Operation.UPLOAD:
                            channel = ClientChannel(sock, queue, address)
                            thread = threading.Thread(target=upload_sack_client_handler, args=(channel, args.storage, stop_event))
                        elif packet.header.flags.type == HeaderFlags.Type.SACK and packet.header.flags.operation == HeaderFlags.Operation.DOWNLOAD:
                            channel = ClientChannel(sock, queue, address)
                            thread = threading.Thread(target=download_sack_client_handler, args=(channel, args.storage, stop_event))
                        else:
                            logger.warning(f"Recibido SYN de {address} con tipo/operación no soportados: {packet.header.flags.type.name}/{packet.header.flags.operation.name}")
                            continue
                        thread.start()
                        conexiones[address] = (queue, thread)

                        queue.put(packet)
                    else:
                        logger.debug(f"Recibido SIN SYN de {address}: {packet}")
                else:
                    conexiones[address][0].put(packet)

            except socket.timeout:
                clean_conexiones(conexiones)
                continue

    except KeyboardInterrupt:
        logger.info(f"Interrupción por el usuario (Ctrl+C). Cerrando {len(conexiones)} conexiones del servidor...")
        stop_event.set()
        for address, (_, thread) in conexiones.items():
            logger.info(f"Esperando finalización de hilo de {address} ...",)
            thread.join()
            logger.info(f"Hilo de {address} FINALIZADO")

    finally:
        sock.close()
        logger.info("Servidor cerrado correctamente.")


def clean_conexiones(conexiones):
    address_thread_finished = []
    for address, (queue, thread) in conexiones.items():
        if not thread.is_alive():
            thread.join()
            address_thread_finished.append(address)
            logging.info(f"Hilo de {address} FINALIZADO")
    for address in address_thread_finished:
        conexiones.pop(address)


if __name__ == "__main__":
    main()