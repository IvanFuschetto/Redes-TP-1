import os
import time
import socket
import logging
import threading
from typing import Callable, BinaryIO

from protocolo import (
    HEADER_SIZE,
    MAX_PAYLOAD,
    MTU,
    ERR_NONE,
    ERR_FILE_EXISTS,
    ERR_FILE_TOO_BIG,
    ERR_INVALID_NAME,
    ERRORES_DESC,
    Packet,
    HeaderFlags,
    SequenceNumber,
    SackPayload,
    MessageSynUpload,
    compute_sack_blocks,
)

TAMANO_VENTANA_DEFAULT = 16
TIMEOUT_RETRANSMISION_DEFAULT = 0.4
MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MiB


def calcular_bloques_sack(buffer_desordenado: dict, expected_seq: int) -> list[tuple[int, int]]:
    """
    Calcula los bloques contiguos SACK [(start, end), ...] respetando la aritmética circular
    a partir del número de secuencia esperado.
    """
    if not buffer_desordenado:
        return []
    return compute_sack_blocks(set(buffer_desordenado.keys()), expected_seq)


def crear_paquete_ack(
    ack_number: int,
    sack_blocks: list[tuple[int, int]],
    sequence_number: int,
    operation: HeaderFlags.Operation
) -> Packet:
    """Crea un paquete de confirmación ACK con bloques SACK serializados en el payload."""
    payload_sack = SackPayload(sack_blocks).serialize()
    flags = HeaderFlags(
        type=HeaderFlags.Type.SACK,
        operation=operation,
        ack=True,
        syn=False,
        fin=False,
        error=ERR_NONE
    )
    return Packet(
        sequence_number=sequence_number,
        ack_number=ack_number,
        flags=flags,
        payload=payload_sack
    )


def crear_paquete_datos(sequence_number: int, payload: bytes, operation: HeaderFlags.Operation) -> Packet:
    """Crea un paquete con datos de archivo para el protocolo SACK."""
    flags = HeaderFlags(
        type=HeaderFlags.Type.SACK,
        operation=operation,
        ack=False,
        syn=False,
        fin=False,
        error=ERR_NONE
    )
    return Packet(
        sequence_number=sequence_number,
        ack_number=0,
        flags=flags,
        payload=payload
    )


class EmisorSack:
    """
    Motor genérico de transmisión con Ventana Deslizante y SACK (Selective Repeat).
    Funciona de manera idéntica tanto para el Servidor (Download) como para el Cliente (Upload).
    """
    def __init__(
        self,
        bloques: list[bytes],
        secuencia_inicial: int,
        operation: HeaderFlags.Operation,
        enviar_pkt_fn: Callable[[Packet], None],
        recibir_ack_fn: Callable[[], Packet | None],
        tamano_ventana: int = TAMANO_VENTANA_DEFAULT,
        timeout_retransmision: float = TIMEOUT_RETRANSMISION_DEFAULT,
        stop_event: threading.Event | None = None
    ):
        self.bloques = bloques if bloques else [b""]
        self.total_bloques = len(self.bloques)
        self.base_seq = secuencia_inicial
        self.proximo_seq = secuencia_inicial
        self.operation = operation
        self.enviar_pkt_fn = enviar_pkt_fn
        self.recibir_ack_fn = recibir_ack_fn
        self.tamano_ventana = tamano_ventana
        self.timeout_retransmision = timeout_retransmision
        self.stop_event = stop_event or threading.Event()

        self.paquetes_no_confirmados: dict[int, tuple[Packet, float]] = {}
        self.bloques_recibidos_por_sack: set[int] = set()
        self.ultimo_ack: int = (secuencia_inicial - 1) % 256
        self.contador_dup_acks: int = 0

    def transmitir(self, max_inactividad: float = 15.0) -> int:
        """
        Ejecuta la transmisión completa de los bloques hasta que todos sean confirmados.
        Retorna el siguiente número de secuencia para el FIN.
        """
        indice_bloque = 0
        ultimo_avance = time.monotonic()

        while (indice_bloque < self.total_bloques or self.paquetes_no_confirmados) and not self.stop_event.is_set():
            if time.monotonic() - ultimo_avance > max_inactividad:
                raise TimeoutError(f"[EMISOR SACK] Tiempo de espera agotado sin confirmaciones ({max_inactividad}s).")

            # 1. Enviar paquetes mientras haya cupo en la ventana activa
            while indice_bloque < self.total_bloques and SequenceNumber.is_in_window(self.proximo_seq, self.base_seq, self.tamano_ventana):
                paquete = crear_paquete_datos(self.proximo_seq, self.bloques[indice_bloque], self.operation)
                self.enviar_pkt_fn(paquete)
                self.paquetes_no_confirmados[self.proximo_seq] = (paquete, time.monotonic())

                self.proximo_seq = SequenceNumber.next_seq(self.proximo_seq)
                indice_bloque += 1
                ultimo_avance = time.monotonic()

            # 2. Leer confirmaciones ACK/SACK
            paquete_ack = self.recibir_ack_fn()
            if paquete_ack is not None and paquete_ack.header.flags.ack:
                ack_acumulativo = paquete_ack.header.ack_number
                ultimo_avance = time.monotonic()

                # 2.1 Procesar bloques SACK presentes en payload
                if paquete_ack.payload:
                    sack_payload = SackPayload.deserialize(paquete_ack.payload)
                    for inicio, fin in sack_payload.blocks:
                        curr = inicio
                        for _ in range(256):
                            self.bloques_recibidos_por_sack.add(curr)
                            if curr == fin:
                                break
                            curr = SequenceNumber.next_seq(curr)

                # 2.2 Detección de ACK Duplicado vs ACK Nuevo
                if ack_acumulativo == self.ultimo_ack:
                    self.contador_dup_acks += 1
                    logging.debug(f"[EMISOR SACK] ACK duplicado ({self.contador_dup_acks}/3) -> ACK={ack_acumulativo}")
                    # Fast Retransmit al 3er ACK duplicado
                    if self.contador_dup_acks == 3:
                        if self.base_seq in self.paquetes_no_confirmados:
                            pkt_faltante, _ = self.paquetes_no_confirmados[self.base_seq]
                            logging.info(f"[EMISOR SACK] ¡3 ACKs duplicados! Fast Retransmit de SEQ base={self.base_seq}")
                            self.enviar_pkt_fn(pkt_faltante)
                            self.paquetes_no_confirmados[self.base_seq] = (pkt_faltante, time.monotonic())
                        self.contador_dup_acks = 0
                elif self.paquetes_no_confirmados and SequenceNumber.is_in_window(ack_acumulativo, self.base_seq, self.tamano_ventana):
                    # 2.3 Deslizar la ventana acumulativa para un ACK nuevo
                    self.ultimo_ack = ack_acumulativo
                    self.contador_dup_acks = 0

                    curr_base = self.base_seq
                    for _ in range(256):
                        self.paquetes_no_confirmados.pop(curr_base, None)
                        self.bloques_recibidos_por_sack.discard(curr_base)
                        if curr_base == ack_acumulativo:
                            break
                        curr_base = SequenceNumber.next_seq(curr_base)
                    self.base_seq = SequenceNumber.next_seq(ack_acumulativo)

            # 3. Retransmisión quirúrgica por timeout
            ahora = time.monotonic()
            for seq_num, (pkt_guardado, timestamp_envio) in list(self.paquetes_no_confirmados.items()):
                if seq_num not in self.bloques_recibidos_por_sack and (ahora - timestamp_envio) > self.timeout_retransmision:
                    logging.debug(f"[EMISOR SACK] Retransmitiendo paquete SEQ={seq_num}")
                    self.enviar_pkt_fn(pkt_guardado)
                    self.paquetes_no_confirmados[seq_num] = (pkt_guardado, ahora)

        return self.proximo_seq


class ReceptorSack:
    """
    Motor genérico de recepción con reordenamiento SACK y almacenamiento en disco.
    Funciona de manera idéntica tanto para el Cliente (Download) como para el Servidor (Upload).
    """
    def __init__(
        self,
        archivo_abierto: BinaryIO,
        secuencia_esperada_inicial: int,
        secuencia_ack_inicial: int,
        operation: HeaderFlags.Operation,
        enviar_ack_fn: Callable[[Packet], None],
        recibir_pkt_fn: Callable[[], Packet | None],
        stop_event: threading.Event | None = None
    ):
        self.archivo_abierto = archivo_abierto
        self.numero_secuencia_esperado = secuencia_esperada_inicial
        self.siguiente_sn_ack = secuencia_ack_inicial
        self.operation = operation
        self.enviar_ack_fn = enviar_ack_fn
        self.recibir_pkt_fn = recibir_pkt_fn
        self.stop_event = stop_event or threading.Event()

        self.received_buffer: dict[int, bytes] = {}

    def procesar_paquete(self, paquete: Packet) -> tuple[bool, Packet | None]:
        """
        Procesa un único paquete entrante.
        Retorna: (es_fin: bool, paquete_fin: Packet | None)
        """
        flags = paquete.header.flags

        if flags.error != ERR_NONE:
            desc = ERRORES_DESC.get(flags.error, f"Error {flags.error}")
            raise RuntimeError(f"Error reportado por el emisor ({flags.error}): {desc}")

        if flags.fin:
            return True, paquete

        # Ignorar paquetes de control puro residuales (SYN retrasado o ACK sin datos)
        if flags.syn or (flags.ack and not paquete.payload):
            return False, None

        seq_num = paquete.header.sequence_number
        payload = paquete.payload or b""

        # Paquete en orden
        if seq_num == self.numero_secuencia_esperado:
            self.archivo_abierto.write(payload)
            self.numero_secuencia_esperado = SequenceNumber.next_seq(self.numero_secuencia_esperado)

            # Drenar paquetes contiguos guardados previamente en el búfer
            while self.numero_secuencia_esperado in self.received_buffer:
                bloque = self.received_buffer.pop(self.numero_secuencia_esperado)
                self.archivo_abierto.write(bloque)
                self.numero_secuencia_esperado = SequenceNumber.next_seq(self.numero_secuencia_esperado)
        else:
            # Paquete fuera de orden: guardar si cae en ventana futura
            distancia = SequenceNumber.distance(seq_num, self.numero_secuencia_esperado)
            if 0 < distancia < 128:
                if seq_num not in self.received_buffer:
                    self.received_buffer[seq_num] = payload

        # Generar bloques SACK y enviar ACK
        sack_blocks = calcular_bloques_sack(self.received_buffer, self.numero_secuencia_esperado)
        ack_num = (self.numero_secuencia_esperado - 1) % 256
        paquete_ack = crear_paquete_ack(ack_num, sack_blocks, self.siguiente_sn_ack, self.operation)
        self.enviar_ack_fn(paquete_ack)

        # Avanzar secuencia del ACK
        self.siguiente_sn_ack = SequenceNumber.next_seq(self.siguiente_sn_ack)
        return False, None

    def recibir_hasta_fin(self, primer_paquete: Packet | None = None, max_inactividad: float = 15.0) -> tuple[Packet, int, int]:
        """
        Escucha continuamente paquetes de datos hasta recibir el FIN.
        Retorna: (paquete_fin, siguiente_sn_ack, numero_secuencia_esperado)
        """
        if primer_paquete is not None:
            es_fin, pkt_fin = self.procesar_paquete(primer_paquete)
            if es_fin:
                return pkt_fin, self.siguiente_sn_ack, self.numero_secuencia_esperado

        ultimo_paquete = time.monotonic()
        while not self.stop_event.is_set():
            paquete = self.recibir_pkt_fn()
            if paquete is None:
                if time.monotonic() - ultimo_paquete > max_inactividad:
                    raise TimeoutError(f"[RECEPTOR SACK] Se superó el tiempo máximo de inactividad ({max_inactividad}s).")
                continue

            ultimo_paquete = time.monotonic()
            es_fin, pkt_fin = self.procesar_paquete(paquete)
            if es_fin:
                return pkt_fin, self.siguiente_sn_ack, self.numero_secuencia_esperado

        raise TimeoutError("[RECEPTOR SACK] Se interrumpió la recepción antes de completar el archivo.")


# =====================================================================
# HANDSHAKE DE CIERRE (FOUR-WAY HANDSHAKE STOP AND WAIT)
# =====================================================================

def ejecutar_cierre_emisor(
    seq_fin_emisor: int,
    operation: HeaderFlags.Operation,
    enviar_fn: Callable[[Packet], None],
    recibir_fn: Callable[[], Packet | None],
    max_intentos: int = 5,
    timeout_inicial: float = 1.0
):
    """
    Four-Way Handshake desde el punto de vista del Emisor (quien inicia el cierre):
      - Paso 1: Envía FIN (seq_fin_emisor).
      - Paso 2: Espera ACK del receptor confirmando su FIN.
      - Paso 3: Espera FIN del receptor.
      - Paso 4: Envía ACK al FIN del receptor.
    """
    paquete_fin = Packet(
        sequence_number=seq_fin_emisor,
        ack_number=0,
        flags=HeaderFlags(
            type=HeaderFlags.Type.SACK,
            operation=operation,
            ack=False,
            syn=False,
            fin=True,
            error=ERR_NONE
        )
    )

    timeout = timeout_inicial
    intentos = 0
    ack_paso2_ok = False
    paquete_fin_receptor = None

    # Paso 1 y 2
    while intentos < max_intentos:
        enviar_fn(paquete_fin)
        t_inicio = time.monotonic()
        while time.monotonic() - t_inicio < timeout:
            resp = recibir_fn()
            if resp is not None:
                flags = resp.header.flags
                if flags.ack and not flags.fin and resp.header.ack_number == seq_fin_emisor:
                    ack_paso2_ok = True
                    break
                if flags.fin and not flags.ack:
                    paquete_fin_receptor = resp
                    ack_paso2_ok = True
                    break
        if ack_paso2_ok:
            break
        intentos += 1
        timeout *= 2

    # Paso 3
    if paquete_fin_receptor is None:
        t_inicio = time.monotonic()
        while time.monotonic() - t_inicio < 5.0:
            resp = recibir_fn()
            if resp is not None and resp.header.flags.fin and not resp.header.flags.ack:
                paquete_fin_receptor = resp
                break

    # Paso 4
    if paquete_fin_receptor is not None:
        seq_ack_cierre = SequenceNumber.next_seq(seq_fin_emisor)
        ack_cierre = Packet(
            sequence_number=seq_ack_cierre,
            ack_number=paquete_fin_receptor.header.sequence_number,
            flags=HeaderFlags(
                type=HeaderFlags.Type.SACK,
                operation=operation,
                ack=True,
                syn=False,
                fin=False,
                error=ERR_NONE
            )
        )
        enviar_fn(ack_cierre)
        enviar_fn(ack_cierre)


def ejecutar_cierre_receptor(
    paquete_fin_emisor: Packet,
    seq_cliente_ack: int,
    operation: HeaderFlags.Operation,
    enviar_fn: Callable[[Packet], None],
    recibir_fn: Callable[[], Packet | None],
    max_intentos: int = 5,
    timeout_inicial: float = 1.0
):
    """
    Four-Way Handshake desde el punto de vista del Receptor (quien recibe el primer FIN):
      - Paso 2: Responde con ACK al FIN recibido (seq_cliente_ack).
      - Paso 3: Envía su propio FIN con Stop and Wait.
      - Paso 4: Espera el ACK del emisor confirmando su FIN.
    """
    # Paso 2
    paquete_ack_fin = Packet(
        sequence_number=seq_cliente_ack,
        ack_number=paquete_fin_emisor.header.sequence_number,
        flags=HeaderFlags(
            type=HeaderFlags.Type.SACK,
            operation=operation,
            ack=True,
            syn=False,
            fin=False,
            error=ERR_NONE
        )
    )
    enviar_fn(paquete_ack_fin)

    # Paso 3
    seq_fin_propio = SequenceNumber.next_seq(seq_cliente_ack)
    paquete_fin_propio = Packet(
        sequence_number=seq_fin_propio,
        ack_number=0,
        flags=HeaderFlags(
            type=HeaderFlags.Type.SACK,
            operation=operation,
            ack=False,
            syn=False,
            fin=True,
            error=ERR_NONE
        )
    )

    timeout = timeout_inicial
    intentos = 0
    # Stop and Wait: enviar propio FIN y esperar ACK (Pasos 3 y 4)
    while intentos < max_intentos:
        enviar_fn(paquete_fin_propio)
        t_inicio = time.monotonic()
        while time.monotonic() - t_inicio < timeout:
            resp = recibir_fn()
            if resp is not None:
                flags = resp.header.flags
                if flags.fin and not flags.ack:
                    enviar_fn(paquete_ack_fin)
                    continue
                if flags.ack and resp.header.ack_number == seq_fin_propio:
                    return
        intentos += 1
        timeout *= 2
