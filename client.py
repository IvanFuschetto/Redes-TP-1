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

        self.base = base
        self.next_seq = next_seq

        # Paquetes enviados y todavía no confirmados
        # por ACK acumulativo.
        self.unacked_packets: dict[int, Packet] = {}

        # Secuencias confirmadas mediante SACK.
        self.sacked_seqs: set[int] = set()

        # RTT estimado
        self.rtt_estimado: float = 1.0
        self.rtt_desviacion: float = 0.25

        # El ACK anterior a base.
        #
        # Si base=0, el anterior es MAX_SEQ.
        self.last_ack_num: int = (
            base - 1 if base > 0 else MAX_SEQ
        )

        self.dup_ack_count: int = 0

        # ---------------------------------------------------------
        # FAST RECOVERY
        # ---------------------------------------------------------

        # Indica si estamos dentro de una recuperación iniciada
        # por ACKs duplicados.
        self.in_recovery: bool = False

        # Último paquete que estaba en vuelo cuando entramos
        # en fast recovery.
        self.recovery_point: int | None = None

        # Paquetes secundarios que ya retransmitimos durante
        # ESTA recuperación.
        #
        # IMPORTANTE:
        #   base NO depende de este conjunto.
        #   base puede retransmitirse nuevamente siempre que
        #   siga siendo base.
        self.fast_retransmitted: set[int] = set()

        # ---------------------------------------------------------
        # TIMER / RTT
        # ---------------------------------------------------------

        self.deadline: float | None = None

        # True si hubo una retransmisión desde que arrancó
        # el intervalo utilizado para obtener la próxima muestra RTT.
        #
        # Si hubo retransmisión, no usamos ese ACK para medir RTT.
        self.rtt_invalidado: bool = False

        # ---------------------------------------------------------
        # TIMEOUTS
        # ---------------------------------------------------------

        self.timeouts_consecutivos: int = 0

    # =============================================================
    # TIMER
    # =============================================================

    def _set_remaining_timeout(self):
        if self.deadline is None:
            return

        remaining = self.deadline - time.monotonic()

        if remaining <= 0:
            remaining = 0.001

        self.sock.settimeout(remaining)

    def _restart_deadline(self):
        self.deadline = time.monotonic() + self.timeout
        self._set_remaining_timeout()

        # Un nuevo intervalo RTT comienza acá.
        #
        # Si hubo una retransmisión antes de este punto,
        # _retransmit() ya puso rtt_invalidado=True.
        #
        # No lo limpiamos acá porque queremos que el próximo
        # ACK sepa que hubo retransmisión.
        pass

    # =============================================================
    # SECUENCIAS
    # =============================================================

    def _next_seq(self, seq: int) -> int:
        return SequenceNumber.next_seq(seq)

    # =============================================================
    # HUECOS
    # =============================================================

    def _huecos(self) -> list[int]:
        """
        Devuelve los paquetes que:

          - fueron enviados,
          - siguen dentro de la ventana actual,
          - NO fueron confirmados acumulativamente,
          - NO están confirmados por SACK.

        Es decir: paquetes pendientes que NO están confirmados
        por SACK.
        """

        huecos = []

        curr = self.base

        while curr != self.next_seq:

            if (
                curr in self.unacked_packets
                and curr not in self.sacked_seqs
            ):
                huecos.append(curr)

            curr = self._next_seq(curr)

        return huecos

    # =============================================================
    # RETRANSMISIÓN
    # =============================================================

    def _retransmit(self, seq: int):
        """
        Retransmite un paquete concreto.

        Toda retransmisión invalida la próxima medición RTT.
        """

        packet = self.unacked_packets.get(seq)

        if packet is None:
            return

        self.sock.sendto(
            packet.serialize(),
            self.server_addr
        )

        # Una retransmisión hace que la próxima medición RTT
        # no sea confiable.
        self.rtt_invalidado = True

        logging.debug(
            f"[CLIENTE] RETRANSMITIDO SEQ={seq}"
        )

    # =============================================================
    # FAST RETRANSMIT DE BASE
    # =============================================================

    def _retransmit_base(self):
        """
        Retransmite SOLAMENTE base.

        Esta es la acción que hacemos ante 3 ACK duplicados
        mientras base todavía no fue confirmada.

        IMPORTANTE:
        No consultamos fast_retransmitted acá.

        Si base sigue bloqueando la ventana, puede y debe
        volver a retransmitirse.
        """

        if self.base not in self.unacked_packets:
            return

        logging.debug(
            f"[FAST] Retransmitiendo BASE={self.base}"
        )

        self._retransmit(self.base)

    # =============================================================
    # RECUPERACIÓN DE HUECOS
    # =============================================================

    def _retransmit_lost_packets(self):
        """
        Durante fast recovery, después de que llegó un ACK NUEVO
        que hizo avanzar base, buscamos los huecos que quedaron
        descubiertos por SACK.

        Los huecos secundarios se retransmiten como máximo una
        vez durante esta recuperación.

        base es un caso especial y NO se bloquea mediante
        fast_retransmitted.
        """

        huecos = self._huecos()

        for seq in huecos:

            # Si seq es base, no usamos fast_retransmitted.
            #
            # base puede necesitar retransmitirse nuevamente
            # porque es justamente el paquete que mantiene
            # bloqueada la ventana.
            if seq == self.base:
                continue

            # Los huecos secundarios solamente se retransmiten
            # una vez por recuperación.
            if seq in self.fast_retransmitted:
                continue

            logging.debug(
                f"[FAST-RECOVERY] Hueco detectado: "
                f"SEQ={seq}"
            )

            self._retransmit(seq)

            self.fast_retransmitted.add(seq)

    # =============================================================
    # COMIENZO DE FAST RECOVERY
    # =============================================================

    def _start_fast_recovery(self):
        """
        Se ejecuta cuando recibimos 3 ACK duplicados.

        PRIMERA ACCIÓN:
            retransmitir solamente base.

        NO retransmitimos todos los huecos acá.
        """

        if self.in_recovery:
            return

        if self.base not in self.unacked_packets:
            return

        self.in_recovery = True

        # Guardamos hasta dónde llegaba la transmisión cuando
        # entramos en recovery.
        #
        # next_seq apunta al próximo paquete a enviar, por lo que
        # el último enviado es el anterior a next_seq.
        recovery_point = self.base

        curr = self.base

        while curr != self.next_seq:
            recovery_point = curr
            curr = self._next_seq(curr)

        self.recovery_point = recovery_point

        # Comenzamos una nueva lista de retransmisiones
        # secundarias.
        self.fast_retransmitted.clear()

        logging.debug(
            f"[FAST-RECOVERY START] "
            f"BASE={self.base}, "
            f"RECOVERY_POINT={self.recovery_point}"
        )

        # PRIMERA RETRANSMISIÓN:
        # solamente base.
        self._retransmit_base()

    # =============================================================
    # ¿TERMINÓ FAST RECOVERY?
    # =============================================================

    def _recovery_finished(self) -> bool:
        """
        Determina si el ACK acumulativo ya llegó hasta
        recovery_point.

        Si recovery_point ya no está dentro de la ventana
        que comienza en base, significa que base avanzó más allá
        del punto donde comenzó la recuperación.
        """

        if not self.in_recovery:
            return False

        if self.recovery_point is None:
            return True

        # Cantidad de paquetes actualmente en vuelo.
        en_vuelo = SequenceNumber.distance(
            self.next_seq,
            self.base
        )

        # Si no hay nada en vuelo, claramente pasamos
        # el recovery point.
        if en_vuelo <= 0:
            return True

        # Si recovery_point sigue dentro de la ventana que comienza
        # en base, todavía no terminamos.
        sigue_en_ventana = SequenceNumber.is_in_window(
            self.recovery_point,
            self.base,
            en_vuelo
        )

        return not sigue_en_ventana

    # =============================================================
    # FINALIZAR FAST RECOVERY
    # =============================================================

    def _finish_fast_recovery(self):
        logging.debug(
            f"[FAST-RECOVERY END] "
            f"BASE={self.base}"
        )

        self.in_recovery = False
        self.recovery_point = None
        self.fast_retransmitted.clear()

    # =============================================================
    # MANEJO DE ACK
    # =============================================================

    def _handle_ack_response(self, ack_packet: Packet):

        ack_num = ack_packet.header.ack_number

        # ---------------------------------------------------------
        # SACK
        # ---------------------------------------------------------

        # Secuencias confirmadas por SACK en este ACK.
        current_sacks: set[int] = set()

        try:
            sack_payload = SackPayload.deserialize(
                ack_packet.payload
            )

            for block in sack_payload.blocks:
                start = block.start
                end = block.end

                curr = start

                while True:

                    # Solamente nos interesan paquetes que
                    # realmente están dentro de nuestra ventana.
                    if curr in self.unacked_packets:
                        current_sacks.add(curr)

                    if curr == end:
                        break

                    curr = self._next_seq(curr)

        except Exception:
            # Si este ACK no contiene SACK válido, simplemente
            # queda sin bloques SACK.
            current_sacks = set()

        # Actualizamos el conjunto global de SACK.
        self.sacked_seqs.update(current_sacks)

        # ---------------------------------------------------------
        # ACK DUPLICADO
        # ---------------------------------------------------------

        if ack_num == self.last_ack_num:

            self.dup_ack_count += 1

            logging.debug(
                f"[CLIENTE] ACK DUPLICADO={ack_num} "
                f"(#{self.dup_ack_count})"
            )

            # Cada grupo de 3 ACK duplicados genera una
            # retransmisión de BASE.
            #
            # IMPORTANTE:
            # aunque ya estemos en recovery, si base no avanzó,
            # seguimos retransmitiendo BASE.
            if self.dup_ack_count % 3 == 0:

                if not self.in_recovery:
                    self._start_fast_recovery()
                else:
                    # Seguimos trabados en la misma base.
                    #
                    # NO mandamos los otros huecos.
                    # Solamente BASE.
                    self._retransmit_base()

            return

        # ---------------------------------------------------------
        # ¿ACK NUEVO VÁLIDO?
        # ---------------------------------------------------------

        if not SequenceNumber.is_in_window(
            ack_num,
            self.base,
            self.window_size
        ):
            logging.debug(
                f"[CLIENTE] ACK fuera de ventana ignorado: "
                f"ACK={ack_num}, BASE={self.base}"
            )
            return

        # ---------------------------------------------------------
        # ACK NUEVO
        # ---------------------------------------------------------

        old_base = self.base

        self.last_ack_num = ack_num
        self.dup_ack_count = 0

        # Un ACK nuevo demuestra que la conexión sigue avanzando.
        self.timeouts_consecutivos = 0

        # ---------------------------------------------------------
        # RTT
        # ---------------------------------------------------------

        rtt_muestra = None

        if (
            not self.rtt_invalidado
            and self.deadline is not None
        ):
            rtt_muestra = (
                self.timeout
                - (self.deadline - time.monotonic())
            )

            if rtt_muestra <= 0:
                rtt_muestra = None

        # ---------------------------------------------------------
        # ACK CUMULATIVO
        # ---------------------------------------------------------

        curr = self.base

        while True:

            self.unacked_packets.pop(curr, None)
            self.sacked_seqs.discard(curr)

            if curr == ack_num:
                break

            curr = self._next_seq(curr)

        # El próximo paquete base pasa a ser el siguiente
        # al ACK acumulativo.
        self.base = self._next_seq(ack_num)

        logging.debug(
            f"[CLIENTE] ACK NUEVO={ack_num} "
            f"BASE {old_base} -> {self.base}"
        )

        # ---------------------------------------------------------
        # RTT
        # ---------------------------------------------------------

        if rtt_muestra is not None:

            self.rtt_estimado = (
                0.875 * self.rtt_estimado
                + 0.125 * rtt_muestra
            )

            self.rtt_desviacion = (
                0.75 * self.rtt_desviacion
                + 0.25 * abs(
                    rtt_muestra - self.rtt_estimado
                )
            )

            self.timeout = min(
                self.rtt_estimado
                + 4 * self.rtt_desviacion,
                MAX_RTO
            )

            logging.debug(
                f"[RTT] muestra={rtt_muestra:.4f}s "
                f"estimado={self.rtt_estimado:.4f}s "
                f"desv={self.rtt_desviacion:.4f}s "
                f"RTO={self.timeout:.4f}s"
            )

        # ---------------------------------------------------------
        # FAST RECOVERY
        # ---------------------------------------------------------

        if self.in_recovery:

            # IMPORTANTE:
            #
            # Recién ahora, después de que BASE avanzó,
            # miramos los SACK y buscamos los huecos.
            self._retransmit_lost_packets()

            # ¿Ya avanzamos más allá del punto de recuperación?
            if self._recovery_finished():
                self._finish_fast_recovery()

        # ---------------------------------------------------------
        # EL ACK FUE NUEVO, POR LO TANTO ARRANCA UN NUEVO
        # INTERVALO DE TIMER.
        # ---------------------------------------------------------

        self.rtt_invalidado = False

        self._restart_deadline()

    # =============================================================
    # TIMEOUT
    # =============================================================

    def _handle_timeout(self):

        self.timeouts_consecutivos += 1

        logging.debug(
            f"[TIMEOUT] "
            f"BASE={self.base}, "
            f"timeout #{self.timeouts_consecutivos}"
        )

        if (
            self.timeouts_consecutivos
            > MAX_TIMEOUTS_CONSECUTIVOS
        ):
            raise TimeoutError(
                "Demasiados timeouts consecutivos "
                f"(base={self.base})"
            )

        # ---------------------------------------------------------
        # Un timeout inicia una nueva recuperación.
        # ---------------------------------------------------------

        self.in_recovery = False
        self.recovery_point = None
        self.fast_retransmitted.clear()

        # Los ACK duplicados anteriores dejan de ser relevantes.
        self.dup_ack_count = 0

        # ---------------------------------------------------------
        # Retransmitir BASE
        # ---------------------------------------------------------

        if self.base in self.unacked_packets:

            self._retransmit_base()

            # Backoff del timeout.
            self.timeout = min(
                self.timeout * 2,
                MAX_RTO
            )

            logging.debug(
                f"[TIMEOUT] Nuevo RTO={self.timeout:.4f}s"
            )

            self._restart_deadline()

    # =============================================================
    # ENVÍO DEL ARCHIVO
    # =============================================================

    def send_file_chunks(self, chunks: list[bytes]):

        chunk_idx = 0
        total_chunks = len(chunks)

        # Arranca el primer intervalo de timeout.
        self._restart_deadline()

        while (
            chunk_idx < total_chunks
            or len(self.unacked_packets) > 0
        ):

            # -----------------------------------------------------
            # LLENAR LA VENTANA
            # -----------------------------------------------------

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

                self.unacked_packets[
                    self.next_seq
                ] = packet

                self.sock.sendto(
                    packet.serialize(),
                    self.server_addr
                )

                logging.debug(
                    f"[CLIENTE] Enviado "
                    f"SEQ={self.next_seq} "
                    f"(Chunk "
                    f"{chunk_idx + 1}/{total_chunks})"
                )

                self.next_seq = (
                    SequenceNumber.next_seq(
                        self.next_seq
                    )
                )

                chunk_idx += 1

            # -----------------------------------------------------
            # ESPERAR ACK
            # -----------------------------------------------------

            self._set_remaining_timeout()

            try:

                raw_data, _ = self.sock.recvfrom(MTU)

                ack_packet = Packet.deserialize(
                    raw_data
                )

                if (
                    ack_packet.header.flags.ack
                    and not ack_packet.header.flags.syn
                    and not ack_packet.header.flags.fin
                ):
                    self._handle_ack_response(
                        ack_packet
                    )

            except BlockingIOError:
                pass

            except socket.timeout:
                self._handle_timeout()

        logging.info(
            "[CLIENTE] "
            "Transferencia de datos completada con éxito."
        )



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

