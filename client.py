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
    MessageSynUpload
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
                raise NotImplementedError("Protocolo SACK no implementado.")
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

class SackSenderClient:
    def __init__(self, sock: socket.socket, server_addr: tuple, window_size: int = 4, timeout: float = 0.5):
        self.sock = sock
        self.server_addr = server_addr
        self.window_size = window_size
        self.timeout = timeout

        # Estado de la ventana
        self.base = 0                               # SEQ del paquete más antiguo pendiente de ACK
        self.next_seq = 0                           # Próximo SEQ libre para asignar a un nuevo paquete
        self.unacked_packets: dict[int, Packet] = {} # seq -> Packet enviado pendiente
        self.sacked_seqs: set[int] = set()           # SEQs informados en bloques SACK (para saber qué no retransmitir)

        # Control de Retransmisión Rápida (Fast Retransmit)
        self.last_ack_num: int | None = None
        self.dup_ack_count: int = 0

        # Timer único asociado al paquete 'base'
        self.timer_start: float | None = None



    def send_file_chunks(self, chunks: list[bytes]):
        chunk_idx = 0
        total_chunks = len(chunks)

        self.sock.settimeout(0.02)

        while chunk_idx < total_chunks or len(self.unacked_packets) > 0: #Vamos a enviar paquetes mientras haya chunks por enviar o paquetes pendientes de ACK


            # 1. ENVIAR NUEVOS PAQUETES (Si la ventana lo permite) Nuestro guia es el puntero a la base de la ventana y el tamaño de la ventana
 

            ## Vamos a enviar paquetes mientras tengamos chunks por enviar y la ventana lo permita
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
                #Enviamos paquete
                self.sock.sendto(packet.serialize(), self.server_addr)
                print(f"[CLIENTE] Enviado SEQ={self.next_seq} (Chunk {chunk_idx + 1}/{total_chunks})")


                #Ignorar por ahora los timers
                if self.timer_start is None:
                    self.timer_start = time.time()

                #Suma en 1 el numero de sequencia y si el mayor a 256 lo mapea en el circulo (Ej 256 va a ser ns= 0) SIempre mantiene forma circular
                self.next_seq = SequenceNumber.next_seq(self.next_seq)
                
                #Hay que avanzar los chunks(A checkear)
                chunk_idx += 1


            # 2. PROCESAR RESPUESTAS ACK / SACK

            try:
                #Recibimos paquete
                raw_data, _ = self.sock.recvfrom(MTU)
                ack_packet = Packet.deserialize(raw_data)

                #Cheakeamos que el paquete recibido sea un ACK
                if ack_packet.header.flags.ack:
                    self._handle_ack_response(ack_packet)

            except (socket.timeout, BlockingIOError):
                pass


            # 3. VERIFICAR TIMEOUT (Paquete base)
            if self.timer_start is not None and (time.time() - self.timer_start > self.timeout):
                self._handle_timeout()

        print("[CLIENTE] Transferencia completada con éxito.")

    def _handle_ack_response(self, ack_packet: Packet):
        ack_num = ack_packet.header.ack_number
        #Solo tomas los sacks faltaria algo que tome el payload = datos (bytes crudos) que seria rango del sack * 2
        sack_info = SackPayload.deserialize(ack_packet.payload)

        # 1. Guardar la información SACK únicamente como referencia/registro
        # CADA FOR VA A TENER (3,4) Start = 3 y End = 4 Por ejemplo
        for start, end in sack_info.blocks:
            curr = start
            while True:
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
            print(f"[CLIENTE] ACK duplicado recibido ({self.dup_ack_count}/3) -> ACK={ack_num}")

            # Disparo de Retransmisión Rápida (Fast Retransmit)
            if self.dup_ack_count == 3:
                print(f"[CLIENTE] ¡3 ACKs duplicados! Fast Retransmit sobre SEQ base={self.base}")
                self._retransmit_base()
                self.dup_ack_count = 0  # Reiniciar contador tras retransmitir

        else:
            # CASO ACK NUEVO (Avanza la ventana) 
            self.last_ack_num = ack_num
            self.dup_ack_count = 0  # Resetea el contador de duplicados

            if self.unacked_packets and SequenceNumber.is_in_window(ack_num, self.base, self.window_size):
                # Liberar confirmados hasta ack_num
                curr = self.base
                while True:
                    self.unacked_packets.pop(curr, None)
                    self.sacked_seqs.discard(curr)
                    if curr == ack_num:
                        break
                    curr = SequenceNumber.next_seq(curr)

                # Avanzar la base de la ventana
                self.base = SequenceNumber.next_seq(ack_num)
                print(f"[CLIENTE] ACK nuevo recibido={ack_num}. Nueva base={self.base}")

                # Reiniciar/Apagar Timer
                if len(self.unacked_packets) > 0:
                    self.timer_start = time.time()
                else:
                    self.timer_start = None

    def _retransmit_base(self):
        """Auxiliar para retransmitir únicamente el paquete retenido en 'base'."""
        if self.base in self.unacked_packets:
            packet_to_resend = self.unacked_packets[self.base]
            self.sock.sendto(packet_to_resend.serialize(), self.server_addr)
            # Reiniciar timer sobre el paquete recién retransmitido
            self.timer_start = time.time()

    def _handle_timeout(self):
        """Retransmisión por vencimiento de Timer de seguridad."""
        print(f"[CLIENTE] Timeout vencido. Retransmitiendo base SEQ={self.base}")
        self.dup_ack_count = 0  # Resetear contador al disparar timeout
        self._retransmit_base()









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

