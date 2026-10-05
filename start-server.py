import logging
import os.path
import socket
import threading
import time
from queue import Queue, Empty

from parser import server_parse_args
from protocolo import Packet, MessageSynUpload, HeaderFlags, MAX_PACKET_SIZE, ERR_FILE_TOO_BIG, ERR_FILE_EXISTS, \
    ERRORES_DESC, MTU, ERR_NONE, ERR_UNEXPECTED, MAX_SEQ, SACK_WINDOW_SIZE, SequenceNumber, SackPayload, \
    compute_sack_blocks

MAX_FILE_SIZE = 15 * 1024 * 1024
# Inactividad de una conexión SACK. Debe superar MAX_TIMEOUTS_CONSECUTIVOS * MAX_RTO del cliente (20s)
SACK_INACTIVITY_TIMEOUT = 30

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

            #Limpiar threads que ya terminaron
            for address in list(conexiones.keys()):
                queue, thread = conexiones[address]

                if not thread.is_alive():
                    thread.join()
                    del conexiones[address]

                    logger.debug(
                        f"Conexión de {address} eliminada"
                    )

            try:
                packet_bytes, address = sock.recvfrom(MTU)
                packet = Packet.deserialize(packet_bytes)

                if not address in conexiones:
                    if packet.header.flags.syn:
                        logger.info(f"Creando conexión para {address}")
                        queue = Queue()
                        if packet.header.flags.type == HeaderFlags.Type.SAW and packet.header.flags.operation == HeaderFlags.Operation.UPLOAD:
                            thread = threading.Thread(target=upload_saw_client_handler, args=(sock, address, queue, args.storage, stop_event))
                        elif packet.header.flags.type == HeaderFlags.Type.SACK and packet.header.flags.operation == HeaderFlags.Operation.UPLOAD:
                            thread = threading.Thread(target=upload_sack_client_handler, args=(sock, address, queue, args.storage, stop_event))
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
                        file_path = os.path.join("storage", message.file_name)
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
                    #NO debido a que se pude perder este ack de fin y el cliente se queda esperando. Se cierra el archivo y se termina el hilo, pero no se hace break para que pueda reintentar el cliente
                    #break

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
                break

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



class ServerUploadSession:
    """
    Receptor SACK (Selective Repeat) de un UPLOAD.
    Los datos en orden se escriben directo al archivo; los fuera de orden se guardan
    en un buffer hasta que se llene el hueco, y se informan al cliente en bloques SACK.
    """
    def __init__(self, sock, client_addr, file_path: str, file_size: int, first_seq: int):
        self.sock = sock
        self.client_addr = client_addr
        self.file_path = file_path
        self.file_size = file_size

        # Estado del protocolo
        self.rcv_nxt = first_seq                       # Próximo SEQ esperado (0 a 255)
        self.out_of_order: dict[int, bytes] = {}       # SEQ -> payload recibido fuera de orden (dentro de la ventana)

        self.bytes_written = 0
        self.error = ERR_NONE
        self.file = open(file_path, "wb")

    def process_packet(self, packet: Packet):
        seq = packet.header.sequence_number
        payload = packet.payload or b""

        # CASO 1: Paquete esperado -> se escribe y se avanza con lo que ya estaba en el buffer
        if seq == self.rcv_nxt:
            self._write(payload)
            self.rcv_nxt = SequenceNumber.next_seq(self.rcv_nxt)
            while self.rcv_nxt in self.out_of_order:
                self._write(self.out_of_order.pop(self.rcv_nxt))
                self.rcv_nxt = SequenceNumber.next_seq(self.rcv_nxt)

        # CASO 2: Paquete fuera de orden dentro de la ventana (deja un hueco)
        elif SequenceNumber.is_in_window(seq, self.rcv_nxt, SACK_WINDOW_SIZE):
            self.out_of_order.setdefault(seq, payload)

        # CASO 3: Paquete duplicado o viejo (ya fue superado por rcv_nxt) -> solo se reenvía el ACK

        self.send_ack()

    def _write(self, data: bytes):
        if self.error:
            return
        try:
            self.file.write(data)
            self.bytes_written += len(data)
        except Exception as e:
            logging.error(f"{self.client_addr}: Error al escribir en el archivo {self.file_path}: {e}")
            self.error = ERR_UNEXPECTED

    def send_ack(self):
        """Construye y envía el ACK acumulativo (último SEQ en orden) con los bloques SACK."""
        flags = HeaderFlags(
            type=HeaderFlags.Type.SACK,
            operation=HeaderFlags.Operation.UPLOAD,
            ack=True,
            syn=False,
            fin=False,
            error=self.error
        )

        sack_blocks = compute_sack_blocks(set(self.out_of_order), self.rcv_nxt)
        sack_payload = SackPayload(sack_blocks).serialize()

        ack_packet = Packet(
            sequence_number=0,
            ack_number=(self.rcv_nxt - 1) % MAX_SEQ,
            flags=flags,
            payload=sack_payload
        )
        self.sock.sendto(ack_packet.serialize(), self.client_addr)

    def is_complete(self) -> bool:
        return not self.error and self.bytes_written == self.file_size and not self.out_of_order

    def close(self, keep_file: bool):
        if not self.file.closed:
            self.file.close()
        if not keep_file and os.path.exists(self.file_path):
            # Transferencia incompleta: se borra el archivo parcial para permitir reintentar
            os.remove(self.file_path)


def upload_sack_client_handler(sock, address, queue: Queue, storage_path, stop_event: threading.Event):
    session: ServerUploadSession | None = None
    syn_ack_packet = None
    fin_ack_packet = None

    try:
        while not stop_event.is_set():
            try:
                packet_received: Packet = queue.get(block=True, timeout=SACK_INACTIVITY_TIMEOUT)

                # Validación de PROTOCOLO y OPERACIÓN consistentes
                if packet_received.header.flags.type != HeaderFlags.Type.SACK:
                    raise ValueError(f"Protocolo alterado: Recibido de {address}: {packet_received} con protocolo alterado: {packet_received.header.flags.type.name} en lugar de {HeaderFlags.Type.SACK.name}")
                if packet_received.header.flags.operation != HeaderFlags.Operation.UPLOAD:
                    raise ValueError(f"Operación alterada: Recibido de {address}: {packet_received} con operación alterada: {packet_received.header.flags.operation.name} en lugar de {HeaderFlags.Operation.UPLOAD.name}")

                # SYN RECEIVED
                if packet_received.header.flags.syn:
                    if syn_ack_packet is None:
                        message = MessageSynUpload.deserialize(packet_received.payload)
                        file_path = os.path.join("storage", message.file_name)
                        error = validar_upload(message.file_size, file_path)

                        syn_ack_packet = Packet(
                            0,
                            packet_received.header.sequence_number,
                            HeaderFlags(HeaderFlags.Type.SACK, HeaderFlags.Operation.UPLOAD, ack=True, syn=True, fin=False, error=error),
                        )
                        if error:
                            logging.warning(f"Error al intentar recibir: {file_path}. ({error}) {ERRORES_DESC[error]}")
                        else:
                            first_seq = SequenceNumber.next_seq(packet_received.header.sequence_number)
                            session = ServerUploadSession(sock, address, file_path, message.file_size, first_seq)

                    # Si ya se recibió el SYN, se reenvía la misma respuesta
                    sock.sendto(syn_ack_packet.serialize(), address)
                    if syn_ack_packet.header.flags.error:
                        break

                # FIN RECEIVED
                elif packet_received.header.flags.fin:
                    if session is None:
                        continue
                    if fin_ack_packet is None:
                        if packet_received.header.sequence_number != session.rcv_nxt or not session.is_complete():
                            # Faltan datos: se responde con el ACK/SACK actual para que el cliente retransmita
                            logging.warning(f"FIN de {address} con transferencia incompleta ({session.bytes_written}/{session.file_size} bytes)")
                            session.send_ack()
                            continue
                        session.close(keep_file=True)
                        fin_ack_packet = Packet(
                            0,
                            packet_received.header.sequence_number,
                            HeaderFlags(HeaderFlags.Type.SACK, HeaderFlags.Operation.UPLOAD, ack=True, syn=False, fin=True),
                        )
                        logging.info(f"Transferencia de {address} finalizada exitosamente")

                    # Se reenvía si el cliente repite el FIN (se perdió el FIN-ACK). No se hace break por eso mismo
                    sock.sendto(fin_ack_packet.serialize(), address)

                # DATOS
                else:
                    if session is None or fin_ack_packet is not None:
                        continue
                    session.process_packet(packet_received)

            except Empty:
                logging.debug(f"Queue Timeout en client handler de {address}")
                break

            except ValueError as e:
                logging.warning(f"{e}")

    finally:
        if session is not None:
            session.close(keep_file=fin_ack_packet is not None)


if __name__ == "__main__":
    main()