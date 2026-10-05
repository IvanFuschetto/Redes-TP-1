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
    ERRORES_DESC, Packet, HeaderFlags, SequenceNumber, SackPayload ,
    MessageSynUpload, MAX_SEQ, SACK_WINDOW_SIZE
)





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
                upload_sack(sock, server_address, source_path, dest_filename)
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

MAX_TIMEOUTS_CONSECUTIVOS = 20
MAX_RTO = 1.0  # Tope del timeout de retransmisión (segundos).

class SackSenderClient:
    def __init__(self, sock: socket.socket, server_addr: tuple, base: int, next_seq: int, timeout: float, window_size: int = SACK_WINDOW_SIZE):
        self.sock = sock
        self.server_addr = server_addr
        self.window_size = window_size
        self.timeout = timeout

        # Estado de la ventana
        self.base = base                               # SEQ del paquete más antiguo pendiente de ACK
        self.next_seq = next_seq                       # Próximo SEQ libre para asignar
        self.unacked_packets: dict[int, Packet] = {}   # seq -> Packet enviado pendiente
        self.sacked_seqs: set[int] = set()             # SEQs informados en bloques SACK

        # Muestreo de RTT y Estimador Jacobson/Karn
        self.rtt_estimado: float = 1.0
        self.rtt_desviacion: float = 0.25

        # Muestreo de RTT: hora del primer envío de cada SEQ (no es un timer)
        self.send_times: dict[int, float] = {}
        self.retransmitted: set[int] = set()           # SEQs retransmitidos alguna vez (Algoritmo de Karn)

        # Control de Retransmisión Rápida (Fast Retransmit)
        # Empieza en el ACK del SYN-ACK: el servidor responde ACK = base - 1 hasta recibir la base
        self.last_ack_num: int = (base - 1) % MAX_SEQ
        self.dup_ack_count: int = 0
        self.in_recovery = False
        self.recovery_point: int | None = None         # Último SEQ enviado al entrar en recuperación
        self.fast_retransmitted: set[int] = set()      # SEQs ya retransmitidos en la recuperación actual
        self.after_timeout = False                     # No se entra en recuperación hasta recibir un ACK nuevo

        # Timer Único de la Ventana (Asociado a 'base')
        self.deadline: float | None = None
        self.timeouts_consecutivos = 0

    def _set_remaining_timeout(self):
        """Ajusta el timeout del socket según el tiempo restante para el deadline actual."""
        if self.deadline is None:
            return

        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            remaining = 0.001
        self.sock.settimeout(remaining)

    def _restart_deadline(self):
        """Reinicia el deadline del timer único a partir de ahora."""
        self.deadline = time.monotonic() + self.timeout
        self._set_remaining_timeout()

    def _lost_packets(self) -> list[int]:
        """
        Regla de pérdida (RFC 6675): SEQs no confirmados ni informados por SACK, por debajo
        del SEQ más alto informado por SACK. Los posteriores pueden estar todavía en vuelo.
        """
        if not self.sacked_seqs:
            return []
        highest = max(self.sacked_seqs, key=lambda seq: SequenceNumber.distance(seq, self.base))
        lost = []
        curr = self.base
        while curr != highest:
            if curr in self.unacked_packets and curr not in self.sacked_seqs:
                lost.append(curr)
            curr = SequenceNumber.next_seq(curr)
        return lost

    def _retransmit(self, seq: int):
        self.sock.sendto(self.unacked_packets[seq].serialize(), self.server_addr)
        self.retransmitted.add(seq)
        logging.debug(f"[CLIENTE] Retransmitido SEQ={seq}")

    def send_file_chunks(self, chunks: list[bytes]):
        chunk_idx = 0
        total_chunks = len(chunks)

        # Iniciar deadline del timer único para la ventana inicial
        self._restart_deadline()

        while chunk_idx < total_chunks or len(self.unacked_packets) > 0:

            # -----------------------------------------------------------------
            # 1. ENVIAR NUEVOS PAQUETES (Dentro de la Ventana)
            # -----------------------------------------------------------------
            while (chunk_idx < total_chunks and 
                   SequenceNumber.is_in_window(self.next_seq, self.base, self.window_size)):

                flags = HeaderFlags(
                    type=HeaderFlags.Type.SACK,
                    operation=HeaderFlags.Operation.UPLOAD,
                    ack=False, syn=False, fin=False, error=ERR_NONE
                )

                packet = Packet(
                    sequence_number=self.next_seq,
                    ack_number=0,
                    flags=flags,
                    payload=chunks[chunk_idx]
                )

                self.unacked_packets[self.next_seq] = packet
                self.send_times[self.next_seq] = time.monotonic()
                self.sock.sendto(packet.serialize(), self.server_addr)
                logging.debug(f"[CLIENTE] Enviado SEQ={self.next_seq} (Chunk {chunk_idx + 1}/{total_chunks})")

                self.next_seq = SequenceNumber.next_seq(self.next_seq)
                chunk_idx += 1

            # Mantener el socket sincronizado con el tiempo restante antes de esperar datos
            self._set_remaining_timeout()

            # -----------------------------------------------------------------
            # 2. PROCESAR RESPUESTAS ACK / SACK Y TIMEOUTS
            # -----------------------------------------------------------------
            try:
                raw_data, _ = self.sock.recvfrom(MTU)
                ack_packet = Packet.deserialize(raw_data)

                if ack_packet.header.flags.ack and not ack_packet.header.flags.syn and not ack_packet.header.flags.fin:
                    self._handle_ack_response(ack_packet)

            except BlockingIOError:
                pass

            except socket.timeout:
                self._handle_timeout()

        logging.info("[CLIENTE] Transferencia de datos completada con éxito.")

    def _handle_ack_response(self, ack_packet: Packet):
        ack_num = ack_packet.header.ack_number
        sack_info = SackPayload.deserialize(ack_packet.payload)

        # 1. Registrar información SACK
        for start, end in sack_info.blocks:
            curr = start
            while True:
                if SequenceNumber.is_in_window(curr, self.base, self.window_size):
                    self.sacked_seqs.add(curr)
                if curr == end:
                    break
                curr = SequenceNumber.next_seq(curr)

        # 2. Lógica de ACK Duplicado vs. ACK Nuevo
        if ack_num == self.last_ack_num:
            self.dup_ack_count += 1
            logging.debug(f"[CLIENTE] ACK duplicado recibido ({self.dup_ack_count}) -> ACK={ack_num}")

            # Con el 3.º duplicado se entra en recuperación rápida y se reenvía SOLO la base.
            # Los duplicados siguientes los generan paquetes que ya estaban en vuelo: no se reenvía nada
            if self.dup_ack_count == 3 and not self.in_recovery and not self.after_timeout:
                logging.debug(f"[CLIENTE] Fast Retransmit gatillado: reenviando base={self.base}")
                self.in_recovery = True
                self.recovery_point = (self.next_seq - 1) % MAX_SEQ
                self.fast_retransmitted = {self.base}
                self._retransmit(self.base)
                self._restart_deadline()

        elif not SequenceNumber.is_in_window(ack_num, self.base, self.window_size):
            logging.debug(f"[CLIENTE] ACK fuera de ventana recibido -> ACK={ack_num}. Ignorando.")

        else:
            # --- ACK NUEVO (Avanza la Base) ---
            # Muestra de RTT (Karn): solo si el paquete nunca se retransmitió ni estaba confirmado por SACK
            rtt_muestra = None
            if ack_num not in self.retransmitted and ack_num not in self.sacked_seqs and ack_num in self.send_times:
                rtt_muestra = time.monotonic() - self.send_times[ack_num]

            # Liberar paquetes confirmados acumulativamente
            curr = self.base
            while True:
                self.unacked_packets.pop(curr, None)
                self.sacked_seqs.discard(curr)
                self.send_times.pop(curr, None)
                self.retransmitted.discard(curr)
                if curr == ack_num:
                    break
                curr = SequenceNumber.next_seq(curr)

            # Avanzar la base
            self.base = SequenceNumber.next_seq(ack_num)
            self.last_ack_num = ack_num
            self.dup_ack_count = 0
            self.timeouts_consecutivos = 0
            self.after_timeout = False
            logging.debug(f"[CLIENTE] ACK nuevo recibido={ack_num}. Nueva base={self.base}")
            
            # Muestreo RTT & Actualización de Timer (Jacobson/Karels. Sin muestra, se conserva el RTO vigente)
            if rtt_muestra is not None:
                self.rtt_estimado = 0.875 * self.rtt_estimado + 0.125 * rtt_muestra
                self.rtt_desviacion = 0.75 * self.rtt_desviacion + 0.25 * abs(rtt_muestra - self.rtt_estimado)
                self.timeout = min(self.rtt_estimado + 4 * self.rtt_desviacion, MAX_RTO)
            self._restart_deadline()

            if self.in_recovery:
                en_vuelo = SequenceNumber.distance(self.next_seq, self.base)
                if not SequenceNumber.is_in_window(self.recovery_point, self.base, en_vuelo):
                    # El ACK cubrió el recovery_point: fin de la recuperación
                    self.in_recovery = False
                else:
                    # ACK parcial: se reenvían los perdidos que todavía no se reenviaron en esta recuperación
                    for seq in self._lost_packets():
                        if seq not in self.fast_retransmitted:
                            self._retransmit(seq)
                            self.fast_retransmitted.add(seq)

    def _handle_timeout(self):
        """Retransmisión POR TIMEOUT: Únicamente reenvía el paquete en 'base'."""
        self.timeouts_consecutivos += 1
        if self.timeouts_consecutivos > MAX_TIMEOUTS_CONSECUTIVOS:
            raise TimeoutError("Error de Conexión: Demasiados timeouts consecutivos.")

        # Se cancela la recuperación rápida y no se vuelve a entrar hasta recibir un ACK nuevo
        self.in_recovery = False
        self.after_timeout = True

        if self.base in self.unacked_packets:
            logging.debug(f"[CLIENTE] Timeout vencido en base={self.base}. Reenviando solo la base.")
            self._retransmit(self.base)

            # Backoff exponencial
            self.timeout = min(self.timeout * 2, MAX_RTO)
        self._restart_deadline()



def stage_fin(sock, address, packet: Packet):
    """
    Envía un paquete FIN y espera la respuesta.
    Devuelve el Packet recibido.
    """

    timeout = 1
    timeout_cont = 0
    while timeout_cont < 5:
        try:
            ack_number_esperado = packet.header.sequence_number
            
            sock.settimeout(timeout)
            
            sock.sendto(packet.serialize(), address)
            
            logging.debug(f"Enviando {packet}")

            tiempo_inicio = time.monotonic()
            while True:

                # Calculamos cuánto tiempo queda del timeout
                tiempo_transcurrido = time.monotonic() - tiempo_inicio
                tiempo_restante = timeout - tiempo_transcurrido

                if tiempo_restante <= 0:
                    raise socket.timeout

                sock.settimeout(tiempo_restante)

                respuesta_bytes, _ = sock.recvfrom(MTU)
                respuesta = Packet.deserialize(respuesta_bytes)

                logging.debug(f"Recibido {respuesta}")
                
                # CASO FIN QUIERO VER FLAG ACK =TRUE  , FIN = 1 
                if respuesta.header.flags.ack and respuesta.header.flags.fin and respuesta.header.ack_number == ack_number_esperado:
                    return (timeout,respuesta)

                # Llegó algo que no nos interesa.
                # Seguimos esperando, pero SIN reiniciar el timeout.
        except socket.timeout:
            logging.debug(f"Timeout {packet}")
            timeout_cont += 1
            timeout *= 2
            continue

    raise TimeoutError("Error de Conexión ! Demasiados Timeouts")


def stage_syn(sock, address, packet: Packet):
    """
    Envía un paquete SYN y espera la respuesta.
    Devuelve el Packet recibido.
    """

    timeout = 1
    timeout_cont = 0
    while timeout_cont < 5:
        try:
            ack_number_esperado = packet.header.sequence_number
            
            sock.settimeout(timeout)
            
            sock.sendto(packet.serialize(), address)
            
            logging.debug(f"Enviando {packet}")

            tiempo_inicio = time.monotonic()
            while True:

                # Calculamos cuánto tiempo queda del timeout
                tiempo_transcurrido = time.monotonic() - tiempo_inicio
                tiempo_restante = timeout - tiempo_transcurrido

                if tiempo_restante <= 0:
                    raise socket.timeout

                sock.settimeout(tiempo_restante)

                respuesta_bytes, _ = sock.recvfrom(MTU)
                respuesta = Packet.deserialize(respuesta_bytes)

                logging.debug(f"Recibido {respuesta}")
                
                # CASO SYN QUIERO VER FLAG ACK =TRUE  , SYN = 1 
                if respuesta.header.flags.ack and respuesta.header.flags.syn and respuesta.header.ack_number == ack_number_esperado:
                    return (timeout,respuesta)

                # Llegó algo que no nos interesa.
                # Seguimos esperando, pero SIN reiniciar el timeout.
        except socket.timeout:
            logging.debug(f"Timeout {packet}")
            timeout_cont += 1
            timeout *= 2
            continue

    raise TimeoutError("Error de Conexión ! Demasiados Timeouts")




def upload_sack(sock, server_address, source_path, dest_filename):
    
    sequence_number = 0

    ### Start SYN
    packet = Packet(
        sequence_number=sequence_number,
        ack_number=0,
        flags=HeaderFlags(
            type=HeaderFlags.Type.SACK,
            operation=HeaderFlags.Operation.UPLOAD,
            ack=False, syn=True, fin=False,
        ),
        payload=MessageSynUpload(
            file_size=os.path.getsize(source_path),
            file_name=dest_filename,
        ).serialize()
    )

    timeout,respuesta = stage_syn(sock, server_address, packet)
    if respuesta.header.flags.error:
        logging.error(f"({respuesta.header.flags.error}) {ERRORES_DESC[respuesta.header.flags.error]}")
        return

    sequence_number += 1

    chunks: list[bytes] = []

    with open(source_path, "rb") as f:
        while True:
            chunk = f.read(MAX_PAYLOAD)
            if not chunk:
                break
            chunks.append(chunk)



    # Envío de chunks con SACK. Si el servidor informa un error en un ACK, se lanza IOError
    sack_client = SackSenderClient(sock, server_address, base=sequence_number, next_seq=sequence_number, window_size=SACK_WINDOW_SIZE, timeout=timeout)
    sack_client.send_file_chunks(chunks)


    # Send FIN
    packet = Packet(
        sequence_number=sack_client.next_seq,
        ack_number=0,
        flags=HeaderFlags(
            type=HeaderFlags.Type.SACK,
            operation=HeaderFlags.Operation.UPLOAD,
            ack=False, syn=False, fin=True,
        )
    )
    _, respuesta = stage_fin(sock, server_address, packet)
    if respuesta.header.flags.error:
        logging.error(f"({respuesta.header.flags.error}) {ERRORES_DESC[respuesta.header.flags.error]}")
        return

    print(f"[CLIENTE] Archivo '{dest_filename}' subido con éxito ({len(chunks)} paquetes).")




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

