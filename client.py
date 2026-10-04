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
                upload_sack(sock, server_address, source_path, dest_filename)
            case _:
                raise ValueError(f"Protocolo {protocol} no implementado.")
    finally:
        sock.close()


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
MIN_RTO = 0.1  # Piso del timeout de retransmisión (segundos)
MAX_RTO = 1.0  # Tope del timeout de retransmisión (segundos). Debe ser bastante menor al timeout de inactividad del servidor (10s)

class SackSenderClient:
    def __init__(self, sock: socket.socket, server_addr: tuple,base:int,next_seq:int ,timeout: float,window_size: int = SACK_WINDOW_SIZE):
        self.sock = sock
        self.server_addr = server_addr
        self.window_size = window_size
        self.timeout = timeout

        # Estado de la ventana
        self.base = base                               # SEQ del paquete más antiguo pendiente de ACK
        self.next_seq =  next_seq                     # Próximo SEQ libre para asignar a un nuevo paquete
        self.unacked_packets: dict[int, Packet] = {} # seq -> Packet enviado pendiente
        self.sacked_seqs: set[int] = set()           # SEQs informados en bloques SACK (para saber qué no retransmitir)
        self.last_retx: dict[int, float] = {}        # seq -> instante de su última retransmisión (un hueco no se reenvía más de una vez por RTT)


        self.send_times: dict[int, float] = {}       # seq -> momento del primer envío (para muestrear RTT)
        self.rtt_muestra: float | None = None

        #valores semilla
        self.rtt_estimado: float | None = None       # se inicializa con la primera muestra (RFC 6298)
        self.rtt_desviacion: float = 0.0



        # Control de Retransmisión Rápida (Fast Retransmit)
        # El ACK "anterior" a la base es el que manda el servidor si se pierde el primer paquete
        self.last_ack_num: int = (base - 1) % MAX_SEQ
        self.dup_ack_count: int = 0

        # Timer único asociado al paquete 'base'
        self.deadline = None
        self.base_retransmited = False
        self.timeouts_consecutivos = 0


    def _set_remaining_timeout(self):

        #no tednria que pasar pero por las dudas
        if self.deadline is None:
            return

        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            remaining = 0.001
        self.sock.settimeout(remaining)

    def _restart_deadline(self):
        self.deadline = time.monotonic() + self.timeout
        self._set_remaining_timeout()


    def send_file_chunks(self, chunks: list[bytes]):
        chunk_idx = 0
        total_chunks = len(chunks)

        # reeincio antes de enviar la ventana entonces ahi ya tengoel timeout actualizado y nunca va a ser none
        self._restart_deadline()

        while chunk_idx < total_chunks or len(self.unacked_packets) > 0: #Vamos a enviar paquetes mientras haya chunks por enviar o paquetes pendientes de ACK


            # 1. ENVIAR NUEVOS PAQUETES (Si la ventana lo permite) Nuestro guia es el puntero a la base de la ventana y el tamaño de la ventana


            ## Se envian paquetes mientras tengamos chunks por enviar y la ventana lo permita
            while (chunk_idx < total_chunks and
                   SequenceNumber.is_in_window(self.next_seq, self.base, self.window_size)):

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

                # Guardamos paquete que vamos a enviaren el diccionario de los paquetes que no se confirmaron
                self.unacked_packets[self.next_seq] = packet
                self.send_times[self.next_seq] = time.monotonic()
                #Enviamos paquete
                self.sock.sendto(packet.serialize(), self.server_addr)
                logging.debug(f"Enviado {packet} (Chunk {chunk_idx + 1}/{total_chunks})")


                #Suma en 1 el numero de sequencia y si el mayor a 256 lo mapea en el circulo (Ej 256 va a ser ns= 0) SIempre mantiene forma circular
                self.next_seq = SequenceNumber.next_seq(self.next_seq)

                chunk_idx += 1

            # La ventana puede haber quedado vacía; el timer queda corriendo sobre la nueva base
            self._set_remaining_timeout()


            # 2. PROCESAR RESPUESTAS ACK / SACK

            try:
                #Recibimos paquete
                raw_data, _ = self.sock.recvfrom(MTU)
                ack_packet = Packet.deserialize(raw_data)

                #Cheakeamos que el paquete recibido sea un ACK de datos (no SYN-ACK ni FIN-ACK viejos)
                if ack_packet.header.flags.ack and not ack_packet.header.flags.syn and not ack_packet.header.flags.fin:
                    self._handle_ack_response(ack_packet)

            except  BlockingIOError:
                pass

            except socket.timeout:
                self._handle_timeout()


        logging.info("Transferencia de datos completada con éxito.")

    def _handle_ack_response(self, ack_packet: Packet):
        if ack_packet.header.flags.error:
            error = ack_packet.header.flags.error
            raise IOError(f"({error}) {ERRORES_DESC.get(error, 'error desconocido')}")

        ack_num = ack_packet.header.ack_number
        #Solo tomas los sacks faltaria algo que tome el payload = datos (bytes crudos) que seria rango del sack * 2
        sack_info = SackPayload.deserialize(ack_packet.payload)

        # 1. Guardar la información SACK (paquetes que el servidor ya tiene y no hay que retransmitir)
        # CADA FOR VA A TENER (3,4) Start = 3 y End = 4 Por ejemplo
        for start, end in sack_info.blocks:
            curr = start
            while True:
                if SequenceNumber.is_in_window(curr, self.base, self.window_size):
                    self.sacked_seqs.add(curr)
                if curr == end:
                    break
                # Para agregar todos los ns que estan en el rango y agregarlos uno por uno
                #Aclaracion como es un set si entra uno dupliicado no pasa nada.
                curr = SequenceNumber.next_seq(curr)

        # 2. Lógica de ACK Nuevo vs. ACK Duplicado
        if ack_num == self.last_ack_num:
            # --- CASO ACK DUPLICADO ---
            self.dup_ack_count += 1
            logging.debug(f"ACK duplicado recibido ({self.dup_ack_count}/3) -> ACK={ack_num}")

            # Disparo de Retransmisión Rápida (Fast Retransmit)
            # A partir del 3er dup ACK, cada nuevo dup ACK puede revelar huecos nuevos (por la info SACK)
            if self.dup_ack_count >= 3:
                self._retransmit_huecos_fast()
        # Habria que analizar que pasa si me llega un paquete con delay de un ack que ya fue confirmado y que ya fue descartado de la ventana. En ese caso no deberia hacer nada.
        elif SequenceNumber.is_in_window(ack_num, self.base, self.window_size) == False:
            logging.debug(f"ACK fuera de ventana recibido -> ACK={ack_num}. Ignorando.")
            self._set_remaining_timeout()
            #Habria que checkear el timepo transcurrido y actualizarlo en la proximo recvfrom

        else:
            # CASO ACK NUEVO (Avanza la ventana)
            self.last_ack_num = ack_num
            self.dup_ack_count = 0  # Resetea el contador de duplicados
            self.timeouts_consecutivos = 0

            # Momento de envío del paquete confirmado (None si fue retransmitido)
            enviado_en = self.send_times.get(ack_num)

            # Liberar confirmados hasta ack_num
            curr = self.base
            while True:
                self.unacked_packets.pop(curr, None)
                self.send_times.pop(curr, None)
                self.sacked_seqs.discard(curr)
                self.last_retx.pop(curr, None)
                if curr == ack_num:
                    break
                curr = SequenceNumber.next_seq(curr)
            # Avanzar la base de la ventana
            self.base = SequenceNumber.next_seq(ack_num)
            logging.debug(f"ACK nuevo recibido={ack_num}. Nueva base={self.base}")

            if self.base_retransmited or enviado_en is None:
                # Algoritmo de Karn: no se toma muestra de RTT de paquetes retransmitidos
                logging.debug(f"Hubo retransmisiones. Reiniciando timer sin muestrear RTT.")
                self.base_retransmited = False
                self._restart_deadline()
            else:
                #formulas (se usan cuando llega un ack limpio sin repetidos antes)
                # Muestra = tiempo desde que se envió el paquete confirmado hasta que llegó su ACK
                self._actualizar_rtt(time.monotonic() - enviado_en)
                self._restart_deadline()

            # ACK parcial: la nueva base quedó en un hueco con paquetes posteriores ya SACKeados.
            # Se reenvía ese hueco ahora (uno por ACK) en vez de esperar otro timeout.
            if self.sacked_seqs:
                self._retransmit_huecos_fast(max_huecos=1)
                #tiempo restante = timeout
                #self.timing_t_interval =  # Reiniciar el timer para la nueva base

    def _actualizar_rtt(self, muestra: float):
        """SRTT / RTTVAR según RFC 6298 (la primera muestra inicializa ambos)."""
        if self.rtt_estimado is None:
            self.rtt_estimado = muestra
            self.rtt_desviacion = muestra / 2
        else:
            self.rtt_desviacion = 0.75*self.rtt_desviacion + 0.25*abs(self.rtt_estimado - muestra)
            self.rtt_estimado = 0.875*self.rtt_estimado + 0.125*muestra
        self.rtt_muestra = muestra
        self.timeout = min(max(self.rtt_estimado + 4*self.rtt_desviacion, MIN_RTO), MAX_RTO)

    def _huecos(self, hasta_ultimo_sack: bool) -> list[int]:
        """
        SEQs pendientes de ACK que el servidor NO informó como recibidos.
        Si `hasta_ultimo_sack`, solo los que están antes del último SEQ SACKeado
        (los posteriores pueden estar todavía en vuelo).
        """
        if hasta_ultimo_sack:
            if not self.sacked_seqs:
                # Sin info SACK, el único hueco seguro es la base
                return [self.base] if self.base in self.unacked_packets else []
            limite = max(self.sacked_seqs, key=lambda seq: SequenceNumber.distance(seq, self.base))
        else:
            limite = self.next_seq

        huecos = []
        curr = self.base
        while curr != limite:
            if curr in self.unacked_packets and curr not in self.sacked_seqs:
                huecos.append(curr)
            curr = SequenceNumber.next_seq(curr)
        return huecos

    def _retransmit(self, seqs: list[int]):
        ahora = time.monotonic()
        for seq in seqs:
            self.send_times.pop(seq, None)
            self.last_retx[seq] = ahora
            self.sock.sendto(self.unacked_packets[seq].serialize(), self.server_addr)
            logging.debug(f"Retransmitido {self.unacked_packets[seq]}")
        if seqs:
            self.base_retransmited = True

    def _handle_timeout(self):
        """Vence el timer de la base: se reenvía SOLO el primer paquete no confirmado (la base)."""
        self.timeouts_consecutivos += 1
        if self.timeouts_consecutivos > MAX_TIMEOUTS_CONSECUTIVOS:
            raise TimeoutError("Error de Conexión ! Demasiados Timeouts")

        huecos = self._huecos(hasta_ultimo_sack=False)[:1]
        logging.debug(f"Timeout vencido (base={self.base}). Retransmitiendo SEQs={huecos}")
        # Agrando el doble la ventana de fin de temporizacion para el siguiente timeout
        self.timeout = min(self.timeout * 2, MAX_RTO)
        self._retransmit(huecos)
        self.dup_ack_count = 0
        # Reiniciar timer sobre los paquetes recién retransmitidos
        self._restart_deadline()

    def _retransmit_huecos_fast(self, max_huecos: int | None = None):
        """
        Reenvía los huecos (anteriores al último SACK) que no se retransmitieron en el último RTT.
        Un hueco se puede reenviar más de una vez si su retransmisión se perdió (sigue sin SACK pasado ~1 RTT).
        """
        ahora = time.monotonic()
        espera = 1.5 * self.rtt_estimado if self.rtt_estimado is not None else self.timeout
        huecos = [seq for seq in self._huecos(hasta_ultimo_sack=True)
                  if ahora - self.last_retx.get(seq, float("-inf")) >= espera]
        if max_huecos is not None:
            huecos = huecos[:max_huecos]
        if huecos:
            logging.debug(f"Fast Retransmit sobre huecos SEQs={huecos}")
            self._retransmit(huecos)
        self._set_remaining_timeout()



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

if __name__ == "__main__":
    main()
