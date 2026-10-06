"""
Mecanismo SACK (Selective Repeat con ACKs selectivos),
independiente del sentido
de la transferencia y de quién es cliente o servidor.
Todo se hace a través de un Channel:

  - SackSender:   emisor con ventana,
        fast retransmit / fast recovery y RTO adaptativo.
  - SackReceiver: receptor que escribe en orden
        y bufferea lo que llega fuera de orden.
  - receive_file: loop del receptor hasta el FIN.
  - send_and_wait / time_wait: utilidades para el
        handshake (SYN) y el cierre (FIN).

UPLOAD:   el cliente usa SackSender y el servidor SackReceiver.
DOWNLOAD: el servidor usa SackSender y el cliente SackReceiver.
"""
import logging
import os
import time

from .channels import Channel
from protocolo import Packet, HeaderFlags, \
    SackPayload, SequenceNumber, compute_sack_blocks, MAX_SEQ, \
    MAX_PAYLOAD, SACK_WINDOW_SIZE, ERR_NONE, ERR_IO_INTERNO, ERRORES_DESC

MAX_TIMEOUTS_CONSECUTIVOS = 20
# Tope del timeout de retransmisión (segundos).
# Debe ser bastante menor al timeout de inactividad del servidor (10s)
MAX_RTO = 1.0
MAX_HANDSHAKE_TIMEOUTS = 5


class RemoteError(Exception):
    """El otro extremo informó un código de error en un ACK."""
    def __init__(self, error: int):
        self.error = error
        super().__init__(f"({error})" +
                         f"{ERRORES_DESC.get(error, 'error desconocido')}")


def sack_flags(operation: HeaderFlags.Operation,
               ack=False,
               syn=False,
               fin=False,
               error=ERR_NONE) -> HeaderFlags:
    return HeaderFlags(HeaderFlags.Type.SACK,
                       operation,
                       ack=ack,
                       syn=syn,
                       fin=fin,
                       error=error)


def read_chunks(path) -> list[bytes]:
    chunks: list[bytes] = []
    with open(path, "rb") as f:
        while chunk := f.read(MAX_PAYLOAD):
            chunks.append(chunk)
    return chunks


# =================================================================
# HANDSHAKE / CIERRE
# =================================================================

def send_and_wait(channel: Channel, packet: Packet,
                  accept, initial_timeout: float = 1.0,
                  max_timeouts: int = MAX_HANDSHAKE_TIMEOUTS) -> tuple[
                      float, Packet]:
    """
    Envía `packet` y espera una respuesta que cumpla `accept(respuesta)`,
    retransmitiendo con backoff exponencial ante timeout.
    Lo que llega y no cumple se descarta SIN reiniciar el timeout.
    Devuelve (timeout utilizado, respuesta).
    """
    timeout = initial_timeout
    for _ in range(max_timeouts):
        channel.send(packet)
        logging.debug(f"Enviando {packet}")
        deadline = time.monotonic() + timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise channel.TimeoutError
                channel.settimeout(remaining)
                respuesta = channel.recv()
                logging.debug(f"Recibido {respuesta}")
                if accept(respuesta):
                    return timeout, respuesta
        except channel.TimeoutError:
            logging.debug(f"Timeout {packet}")
            timeout *= 2

    raise TimeoutError(f"Demasiados timeouts esperando respuesta a {packet}")


def is_response_to(packet: Packet, syn=False, fin=False):
    """Predicado para send_and_wait: ACK
    (con los flags SYN/FIN pedidos) que confirma `packet`."""
    def accept(respuesta: Packet) -> bool:
        flags = respuesta.header.flags
        return (flags.ack and flags.syn == syn
                and
                flags.fin == fin
                and
                respuesta.header.ack_number == packet.header.sequence_number)
    return accept


def time_wait(channel: Channel, last_packet: Packet,
              should_resend, duration: float, stop_event=None) -> None:
    """
    Estado TIME_WAIT: mientras el otro extremo siga enviando
        (ej. repite el FIN porque se perdió
    nuestro FIN-ACK) se le reenvía `last_packet`.
        Termina tras `duration` segundos sin recibir nada.
    """
    channel.settimeout(duration)
    while stop_event is None or not stop_event.is_set():
        try:
            packet = channel.recv()
        except channel.TimeoutError:
            return
        if should_resend(packet):
            channel.send(last_packet)


# =================================================================
# EMISOR
# =================================================================

class SackSender:
    def __init__(
        self,
        channel: Channel,
        operation: HeaderFlags.Operation,
        base: int,
        timeout: float,
        window_size: int = SACK_WINDOW_SIZE
    ):
        self.channel = channel
        self.operation = operation
        self.window_size = window_size
        self.timeout = timeout
        self.tag = f"[SACK {operation.name}]"

        self.base = base
        self.next_seq = base

        # Paquetes enviados y todavía no confirmados por ACK acumulativo.
        self.unacked_packets: dict[int, Packet] = {}

        # Secuencias confirmadas mediante SACK.
        self.sacked_seqs: set[int] = set()

        # RTT estimado
        self.rtt_estimado: float = 1.0
        self.rtt_desviacion: float = 0.25

        # El ACK anterior a base.
        self.last_ack_num: int = (base - 1) % MAX_SEQ
        self.dup_ack_count: int = 0

        # ---------------------------------------------------------
        # FAST RECOVERY
        # ---------------------------------------------------------

        # Indica si estamos dentro de una recuperación
        # iniciada por ACKs duplicados.
        self.in_recovery: bool = False

        # Último paquete que estaba en vuelo cuando entramos en fast recovery.
        self.recovery_point: int | None = None

        # Paquetes secundarios que ya retransmitimos
        # durante ESTA recuperación.
        # IMPORTANTE: base NO depende de este conjunto; puede retransmitirse
        # nuevamente siempre que siga siendo base.
        self.fast_retransmitted: set[int] = set()

        # ---------------------------------------------------------
        # TIMER / RTT
        # ---------------------------------------------------------

        self.deadline: float | None = None

        # True si hubo una retransmisión
        # desde que arrancó el intervalo utilizado
        # para obtener la próxima muestra RTT.
        # Si hubo retransmisión, no usamos ese ACK para medir RTT.
        self.rtt_invalidado: bool = False

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
        self.channel.settimeout(remaining)

    def _restart_deadline(self):
        # Un nuevo intervalo RTT comienza acá.
        # Si hubo una retransmisión antes de este punto,
        # _retransmit() ya puso rtt_invalidado=True y NO lo limpiamos acá.
        self.deadline = time.monotonic() + self.timeout
        self._set_remaining_timeout()

    # =============================================================
    # HUECOS
    # =============================================================

    def _huecos(self) -> list[int]:
        """
        Paquetes enviados, dentro de la ventana actual, que NO fueron
        confirmados acumulativamente ni por SACK.
        """
        huecos = []
        curr = self.base
        while curr != self.next_seq:
            if curr in self.unacked_packets and curr not in self.sacked_seqs:
                huecos.append(curr)
            curr = SequenceNumber.next_seq(curr)
        return huecos

    # =============================================================
    # RETRANSMISIÓN
    # =============================================================

    def _retransmit(self, seq: int):
        """Retransmite un paquete concreto.
        Toda retransmisión invalida la próxima medición RTT."""
        packet = self.unacked_packets.get(seq)
        if packet is None:
            return
        self.channel.send(packet)
        self.rtt_invalidado = True
        logging.debug(f"{self.tag} RETRANSMITIDO SEQ={seq}")

    def _retransmit_base(self):
        """
        Retransmite SOLAMENTE base (ante 3 ACK duplicados o timeout).
        No consultamos fast_retransmitted:
        si base sigue bloqueando la ventana, debe volver a retransmitirse.
        """
        if self.base not in self.unacked_packets:
            return
        logging.debug(f"{self.tag} [FAST] Retransmitiendo BASE={self.base}")
        self._retransmit(self.base)

    def _retransmit_lost_packets(self):
        """
        Durante fast recovery,
        después de que llegó un ACK NUEVO que hizo avanzar base,
        retransmite los huecos que quedaron descubiertos por SACK.
        Los huecos secundarios se retransmiten
        como máximo una vez por recuperación.
        """
        for seq in self._huecos():
            if seq in self.fast_retransmitted:
                continue
            logging.debug(f"{self.tag}" +
                          f"[FAST-RECOVERY] Hueco detectado: SEQ={seq}")
            self._retransmit(seq)
            self.fast_retransmitted.add(seq)

    # =============================================================
    # FAST RECOVERY
    # =============================================================

    def _start_fast_recovery(self):
        """
        Se ejecuta cuando recibimos 3 ACK duplicados.
        PRIMERA ACCIÓN: retransmitir solamente base (NO todos los huecos).
        """
        if self.in_recovery or self.base not in self.unacked_packets:
            return

        self.in_recovery = True

        # Hasta dónde llegaba la transmisión al entrar en recovery:
        # next_seq apunta al próximo paquete
        # a enviar, el último enviado es el anterior.
        self.recovery_point = (self.next_seq - 1) % MAX_SEQ
        self.fast_retransmitted.clear()

        logging.debug(f"{self.tag} [FAST-RECOVERY START] BASE={self.base}," +
                      f"RECOVERY_POINT={self.recovery_point}")
        self._retransmit_base()

    def _recovery_finished(self) -> bool:
        """
        El ACK acumulativo ya pasó recovery_point si este ya no está
        dentro de la ventana en vuelo que comienza en base.
        """
        if not self.in_recovery:
            return False
        if self.recovery_point is None:
            return True

        en_vuelo = SequenceNumber.distance(self.next_seq, self.base)
        if en_vuelo <= 0:
            return True

        return not SequenceNumber.is_in_window(self.recovery_point,
                                               self.base, en_vuelo)

    def _finish_fast_recovery(self):
        logging.debug(f"{self.tag} [FAST-RECOVERY END] BASE={self.base}")
        self.in_recovery = False
        self.recovery_point = None
        self.fast_retransmitted.clear()

    # =============================================================
    # MANEJO DE ACK
    # =============================================================

    def _handle_ack_response(self, ack_packet: Packet):
        ack_num = ack_packet.header.ack_number

        # ---------------------------------------------------------
        # SACK: solo interesan secuencias que siguen en nuestra ventana
        # ---------------------------------------------------------
        for start, end in SackPayload.deserialize(ack_packet.payload).blocks:
            curr = start
            for _ in range(self.window_size):
                if curr in self.unacked_packets:
                    self.sacked_seqs.add(curr)
                if curr == end:
                    break
                curr = SequenceNumber.next_seq(curr)

        # ---------------------------------------------------------
        # ACK DUPLICADO
        # ---------------------------------------------------------
        if ack_num == self.last_ack_num:
            self.dup_ack_count += 1
            logging.debug(f"{self.tag} ACK DUPLICADO={ack_num}" +
                          f"(#{self.dup_ack_count})")

            # Cada grupo de 3 ACK duplicados genera una retransmisión de BASE,
            # aunque ya estemos en recovery (base no avanzó).
            if self.dup_ack_count == 3:
                if not self.in_recovery:
                    self._start_fast_recovery()
                else:
                    self._retransmit_base()
            return

        # ---------------------------------------------------------
        # ¿ACK NUEVO VÁLIDO?
        # ---------------------------------------------------------
        if not SequenceNumber.is_in_window(ack_num, self.base,
                                           self.window_size):
            logging.debug(f"{self.tag} ACK fuera de ventana ignorado: " +
                          f"ACK={ack_num}, BASE={self.base}")
            return

        # ---------------------------------------------------------
        # ACK NUEVO
        # ---------------------------------------------------------
        old_base = self.base
        self.last_ack_num = ack_num
        self.dup_ack_count = 0

        # Un ACK nuevo demuestra que la conexión sigue avanzando.
        self.timeouts_consecutivos = 0

        rtt_muestra = None
        if not self.rtt_invalidado and self.deadline is not None:
            rtt_muestra = self.timeout - (self.deadline - time.monotonic())
            if rtt_muestra <= 0:
                rtt_muestra = None

        # ACK acumulativo
        curr = self.base
        while True:
            self.unacked_packets.pop(curr, None)
            self.sacked_seqs.discard(curr)
            if curr == ack_num:
                break
            curr = SequenceNumber.next_seq(curr)

        self.base = SequenceNumber.next_seq(ack_num)
        logging.debug(f"{self.tag} ACK NUEVO={ack_num} "
                      f"BASE {old_base} -> {self.base}")

        # RTT
        if rtt_muestra is not None:
            self.rtt_estimado = (0.875 * self.rtt_estimado +
                                 0.125 * rtt_muestra
                                 )
            self.rtt_desviacion = (0.75 * self.rtt_desviacion +
                                   0.25 * abs(rtt_muestra -
                                              self.rtt_estimado))
            self.timeout = (min(self.rtt_estimado +
                                4 * self.rtt_desviacion, MAX_RTO))
            logging.debug(
                f"{self.tag} [RTT] muestra={rtt_muestra:.4f}s "
                f"estimado={self.rtt_estimado:.4f}s "
                f"desv={self.rtt_desviacion:.4f}s RTO={self.timeout:.4f}s"
            )

        # FAST RECOVERY: recién ahora, después de que BASE avanzó,
        # miramos los SACK y buscamos los huecos.
        if self.in_recovery:
            self._retransmit_lost_packets()
            if self._recovery_finished():
                self._finish_fast_recovery()

        # El ACK fue nuevo, por lo tanto arranca un nuevo intervalo de timer.
        self.rtt_invalidado = False
        self._restart_deadline()

    # =============================================================
    # TIMEOUT
    # =============================================================

    def _handle_timeout(self):
        self.timeouts_consecutivos += 1
        logging.debug(f"{self.tag} [TIMEOUT] BASE={self.base},"
                      f"timeout #{self.timeouts_consecutivos}")

        if self.timeouts_consecutivos > MAX_TIMEOUTS_CONSECUTIVOS:
            raise TimeoutError(f"Demasiados timeouts consecutivos "
                               f"(base={self.base})")

        # Un timeout inicia una nueva recuperación;
        # los ACK duplicados anteriores dejan de ser relevantes.
        self.in_recovery = False
        self.recovery_point = None
        self.fast_retransmitted.clear()
        self.dup_ack_count = 0

        if self.base in self.unacked_packets:
            self._retransmit_base()
            self.timeout = min(self.timeout * 2, MAX_RTO)
            logging.debug(f"{self.tag} "
                          f"[TIMEOUT] Nuevo RTO={self.timeout:.4f}s")
            self._restart_deadline()

    # =============================================================
    # ENVÍO
    # =============================================================

    def _is_ack(self, packet: Packet) -> bool:
        flags = packet.header.flags
        return (flags.type == HeaderFlags.Type.SACK
                and flags.operation == self.operation
                and flags.ack and not flags.syn and not flags.fin)

    def send_chunks(self, chunks: list[bytes], stop_event=None):
        """
        Envía todos los `chunks` y retorna cuando están todos confirmados.
        Lanza TimeoutError si se pierde la conexión y
        RemoteError si el receptor informa un error.
        """
        chunk_idx = 0
        total_chunks = len(chunks)

        # Arranca el primer intervalo de timeout.
        self._restart_deadline()

        while chunk_idx < total_chunks or self.unacked_packets:
            if stop_event is not None and stop_event.is_set():
                raise InterruptedError("Envío interrumpido")

            # LLENAR LA VENTANA
            while (
                chunk_idx < total_chunks
                and SequenceNumber.is_in_window(
                    self.next_seq, self.base, self.window_size
                )
            ):
                packet = Packet(
                    sequence_number=self.next_seq,
                    ack_number=0,
                    flags=sack_flags(self.operation),
                    payload=chunks[chunk_idx]
                )
                self.unacked_packets[self.next_seq] = packet
                self.channel.send(packet)
                logging.debug(f"{self.tag} Enviado SEQ={self.next_seq} "
                              f"(Chunk {chunk_idx + 1}/{total_chunks})")

                self.next_seq = SequenceNumber.next_seq(self.next_seq)
                chunk_idx += 1

            # ESPERAR ACK
            self._set_remaining_timeout()
            try:
                ack_packet = self.channel.recv()
                if self._is_ack(ack_packet):
                    if ack_packet.header.flags.error:
                        raise RemoteError(ack_packet.header.flags.error)
                    self._handle_ack_response(ack_packet)
            except self.channel.TimeoutError:
                self._handle_timeout()

        logging.info(f"{self.tag} Transferencia " +
                     "de datos completada con éxito.")


# =================================================================
# RECEPTOR
# =================================================================

class SackReceiver:
    """
    Receptor SACK (Selective Repeat).
    Los datos en orden se escriben directo al archivo;
    los fuera de orden se guardan en un buffer hasta que se llene el hueco,
    y se informan al emisor en bloques SACK.
    """
    def __init__(self, channel: Channel,
                 operation: HeaderFlags.Operation,
                 file_path: str,
                 file_size: int,
                 first_seq: int):
        self.channel = channel
        self.operation = operation
        self.file_path = file_path
        self.file_size = file_size

        # Estado del protocolo
        self.rcv_nxt = first_seq   # Próximo SEQ esperado (0 a 255)
        # SEQ -> payload recibido fuera de orden (dentro de la ventana)
        self.out_of_order: dict[int, bytes] = {}

        self.bytes_written = 0
        self.error = ERR_NONE
        self.file = open(file_path, "wb")

    def process_packet(self, packet: Packet):
        seq = packet.header.sequence_number
        payload = packet.payload or b""

        # CASO 1: Paquete esperado ->
        # se escribe y se avanza con lo que ya estaba en el buffer
        if seq == self.rcv_nxt:
            self._write(payload)
            self.rcv_nxt = SequenceNumber.next_seq(self.rcv_nxt)
            while self.rcv_nxt in self.out_of_order:
                self._write(self.out_of_order.pop(self.rcv_nxt))
                self.rcv_nxt = SequenceNumber.next_seq(self.rcv_nxt)

        # CASO 2: Paquete fuera de orden dentro de la ventana (deja un hueco)
        elif SequenceNumber.is_in_window(seq, self.rcv_nxt, SACK_WINDOW_SIZE):
            self.out_of_order.setdefault(seq, payload)

        # CASO 3: Paquete duplicado o viejo
        # (ya fue superado por rcv_nxt) -> solo se reenvía el ACK

        self.send_ack()

    def _write(self, data: bytes):
        if self.error:
            return
        try:
            self.file.write(data)
            self.bytes_written += len(data)
        except Exception as e:
            logging.error(f"{self.channel.address}: "
                          "Error al escribir en el archivo "
                          f"{self.file_path}: {e}")
            self.error = ERR_IO_INTERNO

    def send_ack(self):
        """Envía el ACK acumulativo
        (último SEQ en orden) con los bloques SACK."""
        sack_blocks = compute_sack_blocks(set(self.out_of_order),
                                          self.rcv_nxt)
        ack_packet = Packet(
            sequence_number=0,
            ack_number=(self.rcv_nxt - 1) % MAX_SEQ,
            flags=sack_flags(self.operation, ack=True, error=self.error),
            payload=SackPayload(sack_blocks).serialize()
        )
        self.channel.send(ack_packet)

    def is_complete(self) -> bool:
        return (not self.error
                and self.bytes_written == self.file_size
                and not self.out_of_order)

    def close(self, keep_file: bool):
        if not self.file.closed:
            self.file.close()
        if not keep_file and os.path.exists(self.file_path):
            # Transferencia incompleta:
            # se borra el archivo parcial para permitir reintentar
            os.remove(self.file_path)


def receive_file(channel: Channel,
                 receiver: SackReceiver,
                 on_syn, stop_event=None) -> Packet | None:
    """
    Recibe datos en `receiver` hasta un FIN válido
    (todo recibido en orden),
    lo responde con FIN-ACK y devuelve ese FIN-ACK
    (para reenviarlo en TIME_WAIT). Devuelve None si se interrumpe.
    `on_syn` se invoca si llega un SYN repetido
    (se perdió la respuesta al SYN).
    Lanza TimeoutError si el canal queda inactivo y
    OSError si falla la escritura.
    """
    while stop_event is None or not stop_event.is_set():
        try:
            packet = channel.recv()
        except channel.TimeoutError:
            raise TimeoutError("Inactividad "
                               f"en el canal con {channel.address}")

        flags = packet.header.flags
        if (
            flags.type != HeaderFlags.Type.SACK
            or flags.operation != receiver.operation
        ):
            logging.warning("Protocolo/operación alterados: "
                            f"Recibido de {channel.address}: {packet}")
            continue

        if flags.syn:
            on_syn()

        elif flags.fin:
            if (
                packet.header.sequence_number != receiver.rcv_nxt
                or not receiver.is_complete()
            ):
                # Faltan datos: se responde con el
                # ACK/SACK actual para que el emisor retransmita
                logging.warning(f"FIN de {channel.address} con "
                                "transferencia incompleta "
                                f"({receiver.bytes_written}/"
                                f"{receiver.file_size} bytes)")
                receiver.send_ack()
                continue
            fin_ack = Packet(0, packet.header.sequence_number,
                             sack_flags(receiver.operation,
                                        ack=True, fin=True))
            channel.send(fin_ack)
            return fin_ack

        else:
            receiver.process_packet(packet)
            if receiver.error:
                raise OSError(f"Error de escritura en {receiver.file_path}")

    return None
