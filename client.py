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
MAX_RTO = 1.0  # Tope del timeout de retransmisión (segundos). Debe ser bastante menor al timeout de inactividad del servidor (10s)



class SackSenderClient:
    def __init__(
        self,
        sock: socket.socket,
        server_addr: tuple,
        base: int,
        next_seq: int,
        timeout: float,
        window_size: int = SACK_WINDOW_SIZE
    ):
        self.sock = sock
        self.server_addr = server_addr
        self.window_size = window_size
        self.timeout = timeout

        # ------------------------------------------------------------
        # Estado de la ventana
        # ------------------------------------------------------------
        self.base = base
        self.next_seq = next_seq

        self.unacked_packets: dict[int, Packet] = {}
        self.sacked_seqs: set[int] = set()

        # ------------------------------------------------------------
        # Muestreo de RTT / Jacobson-Karn
        # ------------------------------------------------------------
        self.rtt_estimado: float = 1.0
        self.rtt_desviacion: float = 0.25

        # ------------------------------------------------------------
        # Control de ACKs duplicados / Fast Retransmit
        #
        # ACK=N significa:
        #     "recibí todos los paquetes hasta N inclusive"
        #
        # Por lo tanto, antes de recibir el primer ACK de datos
        # (por ejemplo ACK=1), el último ACK acumulativo conocido
        # es el paquete anterior a base.
        # ------------------------------------------------------------
        self.last_ack_num: int = (
            base - 1 if base > 0 else MAX_SEQ
        )

        self.dup_ack_count: int = 0

        # True cuando ya hicimos la primera retransmisión masiva
        # de los huecos para el ACK duplicado actual.
        #
        # False:
        #   los primeros 3 duplicados pueden retransmitir huecos.
        #
        # True:
        #   los siguientes grupos de 3 duplicados retransmiten
        #   solamente self.base.
        self.fast_retransmit_holes_done: bool = False

        # ------------------------------------------------------------
        # Timer único de la ventana
        # ------------------------------------------------------------
        self.deadline: float | None = None

        # True si la base fue retransmitida y por Karn no debemos
        # utilizar el ACK posterior para calcular RTT.
        self.base_retransmited: bool = False

        self.timeouts_consecutivos = 0

    def _set_remaining_timeout(self):
        """
        Ajusta el timeout del socket según el tiempo restante
        hasta el deadline actual.
        """
        if self.deadline is None:
            return

        remaining = self.deadline - time.monotonic()

        if remaining <= 0:
            remaining = 0.001

        self.sock.settimeout(remaining)

    def _restart_deadline(self):
        """
        Reinicia el deadline del timer único.
        """
        self.deadline = time.monotonic() + self.timeout
        self._set_remaining_timeout()

    def _huecos(self) -> list[int]:
        """
        Devuelve los SEQ que todavía no fueron confirmados ni por
        ACK acumulativo ni por SACK.
        """
        huecos = []

        curr = self.base

        while curr != self.next_seq:

            if (
                curr in self.unacked_packets
                and curr not in self.sacked_seqs
            ):
                huecos.append(curr)

            curr = SequenceNumber.next_seq(curr)

        return huecos

    def send_file_chunks(self, chunks: list[bytes]):
        chunk_idx = 0
        total_chunks = len(chunks)

        # Iniciar deadline para la ventana inicial
        self._restart_deadline()

        while (
            chunk_idx < total_chunks
            or len(self.unacked_packets) > 0
        ):

            # ========================================================
            # 1. ENVIAR NUEVOS PAQUETES DENTRO DE LA VENTANA
            # ========================================================
            while (
                chunk_idx < total_chunks
                and SequenceNumber.is_in_window(
                    self.next_seq,
                    self.base,
                    self.window_size
                )
            ):

                flags = HeaderFlags(
                    type=HeaderFlags.Type.SACK,
                    operation=HeaderFlags.Operation.UPLOAD,
                    ack=False,
                    syn=False,
                    fin=False,
                    error=ERR_NONE
                )

                packet = Packet(
                    sequence_number=self.next_seq,
                    ack_number=0,
                    flags=flags,
                    payload=chunks[chunk_idx]
                )

                self.unacked_packets[self.next_seq] = packet

                self.sock.sendto(
                    packet.serialize(),
                    self.server_addr
                )

                logging.debug(
                    f"[CLIENTE] Enviado SEQ={self.next_seq} "
                    f"(Chunk {chunk_idx + 1}/{total_chunks})"
                )

                self.next_seq = SequenceNumber.next_seq(
                    self.next_seq
                )

                chunk_idx += 1

            # ========================================================
            # 2. ESPERAR ACK / SACK
            # ========================================================
            self._set_remaining_timeout()

            try:
                raw_data, _ = self.sock.recvfrom(MTU)

                ack_packet = Packet.deserialize(raw_data)

                if (
                    ack_packet.header.flags.ack
                    and not ack_packet.header.flags.syn
                    and not ack_packet.header.flags.fin
                ):
                    self._handle_ack_response(ack_packet)

            except BlockingIOError:
                pass

            except socket.timeout:
                self._handle_timeout()

        logging.info(
            "[CLIENTE] Transferencia de datos completada con éxito."
        )

    def _handle_ack_response(self, ack_packet: Packet):

        ack_num = ack_packet.header.ack_number

        print(
            f"[ACK] ack_num={ack_num} "
            f"last_ack={self.last_ack_num} "
            f"dup={self.dup_ack_count} "
            f"base={self.base} "
            f"SACK={sorted(self.sacked_seqs)}"
        )


        sack_info = SackPayload.deserialize(
            ack_packet.payload
        )

        # ============================================================
        # 1. REGISTRAR INFORMACIÓN SACK
        # ============================================================
        for start, end in sack_info.blocks:

            curr = start

            while True:

                if SequenceNumber.is_in_window(
                    curr,
                    self.base,
                    self.window_size
                ):
                    self.sacked_seqs.add(curr)

                if curr == end:
                    break

                curr = SequenceNumber.next_seq(curr)

        # ============================================================
        # 2. ACK DUPLICADO
        # ============================================================
        if ack_num == self.last_ack_num:

            self.dup_ack_count += 1

            logging.debug(
                f"[CLIENTE] ACK duplicado "
                f"#{self.dup_ack_count} -> ACK={ack_num}"
            )

            # --------------------------------------------------------
            # Cada grupo de 3 ACK duplicados provoca una acción.
            #
            # PRIMER GRUPO:
            #     retransmitir los huecos SACK conocidos.
            #
            # SEGUNDO GRUPO Y SIGUIENTES:
            #     retransmitir solamente base.
            # --------------------------------------------------------
            if self.dup_ack_count % 3 == 0:

                grupo = self.dup_ack_count // 3

                logging.debug(
                    f"[CLIENTE] Fast Retransmit "
                    f"grupo #{grupo} para ACK={ack_num}"
                )

                if not self.fast_retransmit_holes_done:

                    # Primera recuperación:
                    # reenviar todos los huecos conocidos.
                    self._retransmit_fast_huecos()

                    self.fast_retransmit_holes_done = True

                else:

                    # Ya reenviamos los huecos una vez.
                    #
                    # Si el ACK sigue trabado, el paquete que está
                    # bloqueando el ACK acumulativo es self.base.
                    self._retransmit_fast_base()

            return

        # ============================================================
        # 3. ACK FUERA DE LA VENTANA
        # ============================================================
        elif not SequenceNumber.is_in_window(
            ack_num,
            self.base,
            self.window_size
        ):

            logging.debug(
                f"[CLIENTE] ACK fuera de ventana recibido "
                f"-> ACK={ack_num}. Ignorando."
            )

            return

        # ============================================================
        # 4. ACK NUEVO -> AVANZA LA BASE
        # ============================================================
        else:

            logging.debug(
                f"[CLIENTE] ACK nuevo recibido={ack_num}"
            )

            # El ACK avanzó.
            self.last_ack_num = ack_num

            # Reiniciar contador de duplicados.
            self.dup_ack_count = 0

            # Una nueva base implica un nuevo ciclo de Fast Retransmit.
            self.fast_retransmit_holes_done = False

            # La conexión está progresando.
            self.timeouts_consecutivos = 0

            # --------------------------------------------------------
            # Liberar todos los paquetes confirmados acumulativamente.
            #
            # Si ACK=5:
            #     se liberan base, ..., 5
            # --------------------------------------------------------
            curr = self.base

            while True:

                self.unacked_packets.pop(curr, None)
                self.sacked_seqs.discard(curr)

                if curr == ack_num:
                    break

                curr = SequenceNumber.next_seq(curr)

            # --------------------------------------------------------
            # Avanzar base al paquete siguiente a ACK.
            # --------------------------------------------------------
            self.base = SequenceNumber.next_seq(
                ack_num
            )

            logging.debug(
                f"[CLIENTE] Nueva base={self.base}"
            )

            # ========================================================
            # RTT / KARN
            # ========================================================

            if self.base_retransmited:

                # No tomar muestra RTT porque el paquete fue
                # retransmitido.
                self.base_retransmited = False

                self._restart_deadline()

            else:

                if self.deadline is not None:

                    rtt_muestra = (
                        self.timeout
                        - (self.deadline - time.monotonic())
                    )

                    if rtt_muestra > 0:

                        self.rtt_estimado = (
                            0.875 * self.rtt_estimado
                            + 0.125 * rtt_muestra
                        )

                        self.rtt_desviacion = (
                            0.75 * self.rtt_desviacion
                            + 0.25 * abs(
                                rtt_muestra
                                - self.rtt_estimado
                            )
                        )

                        self.timeout = min(
                            self.rtt_estimado
                            + 4 * self.rtt_desviacion,
                            MAX_RTO
                        )

                self._restart_deadline()

    def _handle_timeout(self):
        """
        Retransmisión por TIMEOUT.

        El timeout solamente retransmite self.base.
        """
        print(
        f"[TIMEOUT] base={self.base} "
        f"next_seq={self.next_seq} "
        f"consecutivos={self.timeouts_consecutivos}"
        )


        self.timeouts_consecutivos += 1

        if (
            self.timeouts_consecutivos
            > MAX_TIMEOUTS_CONSECUTIVOS
        ):
            raise TimeoutError(
                "Error de Conexión: "
                "Demasiados timeouts consecutivos."
            )

        if self.base in self.unacked_packets:

            logging.debug(
                f"[CLIENTE] Timeout vencido en "
                f"base={self.base}. "
                f"Reenviando solo la base."
            )

            packet_base = self.unacked_packets[
                self.base
            ]

            self.sock.sendto(
                packet_base.serialize(),
                self.server_addr
            )

            # Karn
            self.base_retransmited = True

            # Backoff exponencial
            self.timeout = min(
                self.timeout * 2,
                MAX_RTO
            )

            self._restart_deadline()

    def _retransmit_fast_huecos(self):
        """
        Primera fase de Fast Retransmit.

        Reenvía todos los paquetes que actualmente aparecen
        como huecos según la información SACK.
        """

        huecos = self._huecos()

        print(f"[FAST-HUECOS] base={self.base} next_seq={self.next_seq} huecos={huecos}")

        if not huecos:

            logging.debug(
                "[CLIENTE] Fast Retransmit: "
                "no hay huecos SACK conocidos."
            )

            return

        logging.debug(
            f"[CLIENTE] Fast Retransmit: "
            f"reenviando huecos {huecos}"
        )

        for seq in huecos:

            if seq in self.unacked_packets:

                self.sock.sendto(
                    self.unacked_packets[
                        seq
                    ].serialize(),
                    self.server_addr
                )

        # Como base está incluida entre los huecos cuando el ACK
        # está realmente trabado, también se considera retransmitida.
        if self.base in huecos:
            self.base_retransmited = True

    def _retransmit_fast_base(self):
        """
        Segunda fase de Fast Retransmit.

        Si ya retransmitimos los huecos una vez y el mismo ACK
        sigue llegando duplicado, reenviamos solamente self.base.

        La idea es intentar desbloquear específicamente el paquete
        que impide avanzar el ACK acumulativo.
        """

        print(f"[FAST-BASE] retransmitiendo base={self.base}")
        

        if self.base not in self.unacked_packets:

            logging.debug(
                f"[CLIENTE] Fast Retransmit: "
                f"base={self.base} ya no está pendiente."
            )

            return

        logging.debug(
            f"[CLIENTE] Fast Retransmit: "
            f"ACK sigue trabado. "
            f"Reenviando solamente base={self.base}"
        )

        packet_base = self.unacked_packets[
            self.base
        ]

        self.sock.sendto(
            packet_base.serialize(),
            self.server_addr
        )

        # Karn: no usar posteriormente este ACK para
        # calcular una muestra RTT.
        self.base_retransmited = True



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

    raise TimeoutError("FIN Demasiados Timeouts")


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

    raise TimeoutError("SYN Demasiados Timeouts")




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
        print("Error")
        logging.error(f"({respuesta.header.flags.error}) {ERRORES_DESC[respuesta.header.flags.error]}")
        return

    sequence_number += 1

    #time.sleep(15)  # Pequeña pausa para evitar congestión inicial
    chunks: list[bytes] = []

    with open(source_path, "rb") as f:
        while True:
            chunk = f.read(MAX_PAYLOAD)
            if not chunk:
                break
            chunks.append(chunk)



    # Envío de chunks con SACK. Si el servidor informa un error en un ACK, se lanza IOError
    sack_client = SackSenderClient(sock, server_address, base=sequence_number, next_seq=sequence_number, window_size=SACK_WINDOW_SIZE, timeout=timeout)
    print("[CLIENTE] Enviando archivo con SACK...")
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

