import logging
import os.path
import socket
import threading
import time
from queue import Queue, Empty

from parser import server_parse_args
from protocolo import Packet, MessageSynUpload, HeaderFlags, MAX_PACKET_SIZE, ERR_FILE_TOO_BIG, ERR_FILE_EXISTS, \
    ERRORES_DESC

MAX_FILE_SIZE = 15 * 1024 * 1024

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
            try:
                packet_bytes, address = sock.recvfrom(MAX_PACKET_SIZE)
                packet = Packet.deserialize(packet_bytes)

                if not address in conexiones:
                    if packet.header.flags.syn:
                        logger.info(f"Creando conexión para {address}")
                        queue = Queue()
                        if packet.header.flags.type == HeaderFlags.Type.SAW and packet.header.flags.operation == HeaderFlags.Operation.UPLOAD:
                            thread = threading.Thread(target=upload_saw_client_handler, args=(sock, address, queue, args.storage, stop_event))
                        else:
                            logger.warning(f"Recibido SYN de {address} con tipo/operación no soportados: {packet.header.flags.type.name}/{packet.header.flags.operation.name}")
                            continue
                        thread.start()
                        conexiones[address] = (queue, thread)
                    else:
                        logger.debug(f"Recibido SIN SYN de {address}: {packet}")
                else:
                    conexiones[address][0].put(packet)
            except socket.timeout:
                # Delay para inyectar el KeyboardInterrupt
                time.sleep(0.0001)
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



def upload_saw_client_handler(sock, address, queue: Queue, storage_path, stop_event: threading.Event):
    syn_received = False
    last_packet_sent = None

    last_sequence_number_received = None
    last_sequence_number_sent = None

    file = None

    try:
        while not stop_event.is_set():
            try:
                packet_received: Packet = queue.get(block=True, timeout=10)

                # Validación de PROTOCOLO y OPERACIÓN consistentes
                if packet_received.header.flags.type != HeaderFlags.Type.SAW:
                    raise ValueError(f"Protocolo alterado: Recibido de {address}: {packet_received} con protocolo alterado: {packet_received.header.flags.type.name} en lugar de {HeaderFlags.Type.SAW.name}")
                if packet_received.header.flags.operation != HeaderFlags.Operation.UPLOAD:
                    raise ValueError(f"Operación alterada: Recibido de {address}: {packet_received} con operación alterada: {packet_received.header.flags.operation.name} en lugar de {HeaderFlags.Operation.UPLOAD.name}")

                # SYN RECEIVED
                if packet_received.header.flags.syn:
                    if not syn_received:
                        last_sequence_number_received = packet_received.header.sequence_number
                        message = MessageSynUpload.deserialize(packet_received.payload)
                        file_size = message.file_size
                        file_path = os.path.join(storage_path, message.file_name)
                        error = validar_upload(file_size, file_path)

                        last_sequence_number_sent = 1
                        packet = Packet(
                            last_sequence_number_sent,
                            last_sequence_number_received,
                            HeaderFlags(HeaderFlags.Type.SAW, HeaderFlags.Operation.UPLOAD, ack=True, syn=True, fin=False, error=error),
                        )
                        last_packet_sent = packet
                        syn_received = True
                        sock.sendto(packet.serialize(), address)

                        if not error:
                            file = open(file_path, "wb")
                        else:
                            logging.warning(f"Error al intentar recibir: {file_path}. ({error}) {ERRORES_DESC[error]}")
                            break

                    else:
                        # Ya se recibió paquete SYN. Se reenvía respuesta
                        sock.sendto(last_packet_sent.serialize(), address)

                # FIN RECEIVED
                elif packet_received.header.flags.fin:
                    if file is not None and not file.closed:
                        file.close()
                    last_sequence_number_sent += 1
                    last_sequence_number_sent = last_sequence_number_sent if last_sequence_number_sent < 256 else last_sequence_number_sent - 256
                    last_sequence_number_received = packet_received.header.sequence_number
                    packet = Packet(
                        last_sequence_number_sent,
                        last_sequence_number_received,
                        HeaderFlags(HeaderFlags.Type.SAW, HeaderFlags.Operation.UPLOAD, ack=True, syn=False, fin=True),
                    )
                    last_packet_sent = packet
                    sock.sendto(packet.serialize(), address)
                    logging.info(f"Transferencia de {address} finalizada exitosamente")
                    break

                # OTRO CASO
                else:
                    expected_sequence_number_received = last_sequence_number_received + 1
                    expected_sequence_number_received = expected_sequence_number_received if expected_sequence_number_received < 256 else expected_sequence_number_received - 256
                    if not expected_sequence_number_received == packet_received.header.sequence_number:
                        # Estoy recibiendo un paquete que no espero (o ya lo recibí, o se perdió uno)
                        # Reenvío el último paquete enviado
                        sock.sendto(last_packet_sent.serialize(), address)
                        continue

                    # Recibí el paquete que esperaba
                    # No es FIN ni SYN => Payload son datos a recibir
                    error_code = 0
                    datos = packet_received.payload
                    try:
                        file.write(datos)
                    except Exception as e:
                        logging.error(f"{address}: Error al escribir en el archivo {file.name}: {e}")
                        error_code = 7 # Error inesperado

                    last_sequence_number_sent += 1
                    last_sequence_number_sent = last_sequence_number_sent if last_sequence_number_sent < 256 else last_sequence_number_sent - 256
                    last_sequence_number_received = packet_received.header.sequence_number
                    packet = Packet(
                        last_sequence_number_sent,
                        last_sequence_number_received,
                        HeaderFlags(
                            HeaderFlags.Type.SAW, HeaderFlags.Operation.UPLOAD,
                            ack=True, syn=False, fin=False, error=error_code
                        )
                    )
                    last_packet_sent = packet
                    sock.sendto(packet.serialize(), address)

            except Empty:
                logging.debug(f"Queue Timeout en client handler de {address}")
                continue

            except ValueError as e:
                logging.warning(f"{e}")

    finally:
        if file is not None and not file.closed:
            file.close()


def validar_upload(file_size, file_path):
    if file_size > MAX_FILE_SIZE:
        return ERR_FILE_TOO_BIG
    if os.path.exists(file_path):
        return ERR_FILE_EXISTS
    return 0



if __name__ == "__main__":
    main()