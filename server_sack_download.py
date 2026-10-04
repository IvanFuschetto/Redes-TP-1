import os
import sys
import time
import socket
import logging
import threading
from queue import Queue, Empty

from protocolo import (
    HEADER_SIZE,
    MAX_PAYLOAD,
    MTU,
    ERR_NONE,
    ERR_INVALID_NAME,
    ERRORES_DESC,
    Packet,
    HeaderFlags,
    SequenceNumber,
    SackPayload,
    compute_sack_blocks,
)
from parser import server_parse_args


def atender_cliente_download_sack(
    sock: socket.socket,
    direccion_cliente: tuple[str, int],
    canal_paquetes: Queue,
    directorio_almacenamiento: str,
    stop_event: threading.Event
):
    """
    Hilo trabajador encargado de gestionar la sesión de descarga completa para un cliente específico:
      1. Fase de Handshake (SYN -> SYN-ACK -> ACK) con Stop and Wait.
      2. Fase de Envío de Datos con SACK y Ventana Deslizante.
      3. Fase de Cierre con Four-Way Handshake (Stop and Wait).
    """
    logging.info(f"[SERVIDOR DOWNLOAD SACK] Iniciando atención para cliente {direccion_cliente}")

    try:
        # -------------------------------------------------------------
        # 1. FASE DE HANDSHAKE (SYN / SYN-ACK / ACK)
        # -------------------------------------------------------------
        # Esperar el paquete SYN inicial desde el canal
        try:
            paquete_syn: Packet = canal_paquetes.get(timeout=5.0)
        except Empty:
            logging.warning(f"[SERVIDOR] Timeout esperando paquete SYN de {direccion_cliente}. Abortando.")
            return

        nombre_archivo = paquete_syn.payload.decode(errors="ignore").strip()
        ruta_archivo = os.path.join(directorio_almacenamiento, nombre_archivo)

        logging.info(f"[SERVIDOR] Cliente {direccion_cliente} solicita descargar: '{nombre_archivo}'")

        # Validar si el archivo existe y es accesible
        if not os.path.isfile(ruta_archivo):
            logging.error(f"[SERVIDOR] Archivo no encontrado: '{ruta_archivo}'. Enviando error.")
            paquete_error = Packet(
                sequence_number=1,
                ack_number=paquete_syn.header.sequence_number,
                flags=HeaderFlags(
                    type=HeaderFlags.Type.SACK,
                    operation=HeaderFlags.Operation.DOWNLOAD,
                    ack=True,
                    syn=True,
                    fin=False,
                    error=ERR_INVALID_NAME
                )
            )
            sock.sendto(paquete_error.serialize(), direccion_cliente)
            return

        # Cargar los datos del archivo en memoria divididos en bloques MAX_PAYLOAD
        with open(ruta_archivo, "rb") as archivo:
            contenido = archivo.read()

        bloques = [contenido[i:i + MAX_PAYLOAD] for i in range(0, len(contenido), MAX_PAYLOAD)] if contenido else [b""]
        total_bloques = len(bloques)
        logging.info(f"[SERVIDOR] Archivo '{nombre_archivo}' ({len(contenido)} bytes) dividido en {total_bloques} bloques.")

        # Iniciar handshake Stop and Wait (SYN-ACK -> ACK)
        seq_servidor = 1
        paquete_syn_ack = Packet(
            sequence_number=seq_servidor,
            ack_number=paquete_syn.header.sequence_number,
            flags=HeaderFlags(
                type=HeaderFlags.Type.SACK,
                operation=HeaderFlags.Operation.DOWNLOAD,
                ack=True,
                syn=True,
                fin=False,
                error=ERR_NONE
            )
        )

        timeout_syn_ack = 1.0
        intentos_syn_ack = 0
        max_intentos = 5
        handshake_completado = False

        while intentos_syn_ack < max_intentos and not stop_event.is_set():
            logging.debug(f"[SERVIDOR] Enviando SYN-ACK a {direccion_cliente} (intento {intentos_syn_ack + 1}/{max_intentos})")
            sock.sendto(paquete_syn_ack.serialize(), direccion_cliente)

            try:
                paquete_respuesta: Packet = canal_paquetes.get(timeout=timeout_syn_ack)
                flags_resp = paquete_respuesta.header.flags

                # Si el cliente retransmitió el SYN, reenviamos SYN-ACK de inmediato
                if flags_resp.syn and not flags_resp.ack:
                    continue

                # El cliente confirmó el SYN-ACK con su ACK
                if flags_resp.ack and not flags_resp.syn and paquete_respuesta.header.ack_number == seq_servidor:
                    logging.info(f"[SERVIDOR] Handshake de inicio completado con éxito con {direccion_cliente}.")
                    handshake_completado = True
                    break

            except Empty:
                intentos_syn_ack += 1
                timeout_syn_ack *= 2

        if not handshake_completado:
            logging.warning(f"[SERVIDOR] Se agotaron los reintentos de handshake con {direccion_cliente}. Cancelando.")
            return

        # -------------------------------------------------------------
        # 2. FASE DE ENVÍO DE DATOS CON VENTANA DESLIZANTE Y SACK
        # -------------------------------------------------------------
        tamano_ventana = 16
        timeout_retransmision = 0.4
        base_seq = SequenceNumber.next_seq(seq_servidor)  # (=2)El paquete más viejo que todavía NO fue confirmado (borde izquierdo)
        proximo_seq = base_seq #(=2) El siguiente paquete nuevo que vamos a mandar (borde derecho)
        indice_bloque = 0  # Índice del trozo del archivo en disco (bloque 0, bloque 1, ...)

        paquetes_no_confirmados: dict[int, tuple[Packet, float]] = {}  # seq -> (paquete, timestamp_envio)  # {seq: (paquete, hora_de_envio)}
        bloques_recibidos_por_sack: set[int] = set() # {números que el cliente ya tiene desordenados}

        logging.info(f"[SERVIDOR] Iniciando transmisión SACK de {total_bloques} bloques hacia {direccion_cliente}...")

        #Seguí dando vueltas mientras todavía queden bloques del archivo por mandar O mientras queden paquetes en el aire esperando confirmación". Cuando ambas cosas son falsas, el archivo se terminó de mandar y confirmar al 100%.
        while (indice_bloque < total_bloques or paquetes_no_confirmados) and not stop_event.is_set():
            # 2.1 Enviar todos los paquetes posibles dentro de la ventana activa
            while indice_bloque < total_bloques and SequenceNumber.is_in_window(proximo_seq, base_seq, tamano_ventana):
                paquete_datos = Packet(
                    sequence_number=proximo_seq,
                    ack_number=0,
                    flags=HeaderFlags(
                        type=HeaderFlags.Type.SACK,
                        operation=HeaderFlags.Operation.DOWNLOAD,
                        ack=False,
                        syn=False,
                        fin=False,
                        error=ERR_NONE
                    ),
                    payload=bloques[indice_bloque]
                )
                sock.sendto(paquete_datos.serialize(), direccion_cliente)
                paquetes_no_confirmados[proximo_seq] = (paquete_datos, time.monotonic())

                proximo_seq = SequenceNumber.next_seq(proximo_seq)
                indice_bloque += 1

            # 2.2 Leer confirmaciones (ACKs / SACK) del canal
            try:
                paquete_ack: Packet = canal_paquetes.get(timeout=0.03)
                if paquete_ack.header.flags.ack:
                    ack_acumulativo = paquete_ack.header.ack_number

                    # Extraer bloques SACK del payload
                    if paquete_ack.payload:
                        sack_payload = SackPayload.deserialize(paquete_ack.payload)
                        for inicio_bloque, fin_bloque in sack_payload.blocks:
                            curr_seq = inicio_bloque
                            for _ in range(256):
                                bloques_recibidos_por_sack.add(curr_seq)
                                if curr_seq == fin_bloque:
                                    break
                                curr_seq = SequenceNumber.next_seq(curr_seq)

                    # Avanzar base acumulativa si el ACK cae en la ventana
                    if paquetes_no_confirmados and SequenceNumber.is_in_window(ack_acumulativo, base_seq, tamano_ventana):
                        curr_base = base_seq
                        for _ in range(256):
                            paquetes_no_confirmados.pop(curr_base, None)
                            bloques_recibidos_por_sack.discard(curr_base)
                            if curr_base == ack_acumulativo:
                                break
                            curr_base = SequenceNumber.next_seq(curr_base)
                        base_seq = SequenceNumber.next_seq(ack_acumulativo)

            except Empty:
                pass

            # 2.3 Retransmisión por timeout de paquetes no confirmados ni sacked
            ahora = time.monotonic()
            for seq_num, (pkt_guardado, timestamp_envio) in list(paquetes_no_confirmados.items()):
                if seq_num not in bloques_recibidos_por_sack and (ahora - timestamp_envio) > timeout_retransmision:
                    logging.debug(f"[SERVIDOR] Retransmitiendo bloque SEQ={seq_num} a {direccion_cliente}")
                    sock.sendto(pkt_guardado.serialize(), direccion_cliente)
                    paquetes_no_confirmados[seq_num] = (pkt_guardado, ahora)

        logging.info(f"[SERVIDOR] Todos los bloques de '{nombre_archivo}' fueron transmitidos y confirmados por {direccion_cliente}.")

        # -------------------------------------------------------------
        # 3. FASE DE CIERRE: FOUR-WAY HANDSHAKE (STOP AND WAIT)
        # -------------------------------------------------------------
        # Paso 1: Servidor envía FIN
        seq_fin_servidor = proximo_seq
        paquete_fin_servidor = Packet(
            sequence_number=seq_fin_servidor,
            ack_number=0,
            flags=HeaderFlags(
                type=HeaderFlags.Type.SACK,
                operation=HeaderFlags.Operation.DOWNLOAD,
                ack=False,
                syn=False,
                fin=True,
                error=ERR_NONE
            )
        )

        timeout_fin = 1.0
        intentos_fin = 0
        ack_fin_servidor_recibido = False

        while intentos_fin < max_intentos and not stop_event.is_set():
            logging.info(f"[SERVIDOR] Enviando FIN (Paso 1) con SEQ={seq_fin_servidor} a {direccion_cliente} (intento {intentos_fin + 1}/{max_intentos})")
            sock.sendto(paquete_fin_servidor.serialize(), direccion_cliente)

            try:
                paquete_resp_fin: Packet = canal_paquetes.get(timeout=timeout_fin)
                flags_f = paquete_resp_fin.header.flags

                # Paso 2: ACK del cliente al FIN del servidor
                if flags_f.ack and not flags_f.fin and paquete_resp_fin.header.ack_number == seq_fin_servidor:
                    logging.info(f"[SERVIDOR] ACK al FIN del servidor recibido de {direccion_cliente} (Paso 2).")
                    ack_fin_servidor_recibido = True
                    break

            except Empty:
                intentos_fin += 1
                timeout_fin *= 2

        if not ack_fin_servidor_recibido:
            logging.warning(f"[SERVIDOR] Timeout esperando ACK al FIN de {direccion_cliente}.")
            return

        # Paso 3: Esperar FIN del cliente
        timeout_espera_fin_cliente = 5.0
        try:
            while not stop_event.is_set():
                paquete_fin_cliente: Packet = canal_paquetes.get(timeout=timeout_espera_fin_cliente)
                flags_fc = paquete_fin_cliente.header.flags

                if flags_fc.fin and not flags_fc.ack:
                    seq_cliente_fin = paquete_fin_cliente.header.sequence_number
                    logging.info(f"[SERVIDOR] FIN del cliente recibido con SEQ={seq_cliente_fin} de {direccion_cliente} (Paso 3).")

                    # Paso 4: Servidor responde ACK al FIN del cliente
                    seq_ack_cierre = SequenceNumber.next_seq(seq_fin_servidor)
                    paquete_ack_fin_cliente = Packet(
                        sequence_number=seq_ack_cierre,
                        ack_number=seq_cliente_fin,
                        flags=HeaderFlags(
                            type=HeaderFlags.Type.SACK,
                            operation=HeaderFlags.Operation.DOWNLOAD,
                            ack=True,
                            syn=False,
                            fin=False,
                            error=ERR_NONE
                        )
                    )
                    # Enviamos confirmación doble para mayor resiliencia ante pérdidas de último paquete
                    sock.sendto(paquete_ack_fin_cliente.serialize(), direccion_cliente)
                    sock.sendto(paquete_ack_fin_cliente.serialize(), direccion_cliente)
                    logging.info(f"[SERVIDOR] ACK final enviado (Paso 4). Transferencia completada exitosamente para {direccion_cliente}.")
                    break

        except Empty:
            logging.warning(f"[SERVIDOR] Timeout esperando FIN del cliente {direccion_cliente}.")

    except Exception as e:
        logging.exception(f"[SERVIDOR] Error inesperado atendiendo a {direccion_cliente}: {e}")

    finally:
        logging.info(f"[SERVIDOR] Hilo de atención para {direccion_cliente} finalizado.")


def servidor_sack_download(
    host: str,
    port: int,
    directorio_almacenamiento: str,
    stop_event: threading.Event | None = None
):
    """
    Bucle principal del servidor SACK Download:
      - Escucha en el socket UDP central.
      - Al recibir un SYN de una nueva dirección, crea un canal (Queue) y un hilo trabajador.
      - Enruta todos los paquetes subsiguientes de esa dirección al canal del hilo correspondiente.
      - Limpia periódicamente las conexiones finalizadas.
    """
    if stop_event is None:
        stop_event = threading.Event()

    if not os.path.isdir(directorio_almacenamiento):
        os.makedirs(directorio_almacenamiento, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(0.5)  # Permite verificar periódicamente conexiones terminadas y stop_event

    # Diccionario de conexiones activas: direccion (ip, puerto) -> (canal_cola, hilo_trabajador)
    conexiones: dict[tuple[str, int], tuple[Queue, threading.Thread]] = {}

    logging.info(f"[SERVIDOR SACK DOWNLOAD] Escuchando en {host}:{port}")
    logging.info(f"[SERVIDOR SACK DOWNLOAD] Directorio de almacenamiento: '{directorio_almacenamiento}'")

    try:
        while not stop_event.is_set():
            # 1. Limpieza de hilos que ya terminaron su trabajo
            for direccion in list(conexiones.keys()):
                canal, hilo = conexiones[direccion]
                if not hilo.is_alive():
                    hilo.join()
                    del conexiones[direccion]
                    logging.debug(f"[SERVIDOR] Conexión de {direccion} cerrada y liberada.")

            # 2. Recepción de paquetes en el socket central
            try:
                datos, direccion = sock.recvfrom(MTU)
            except socket.timeout:
                continue

            try:
                paquete = Packet.deserialize(datos)
            except Exception as e:
                logging.warning(f"[SERVIDOR] Paquete corrupto recibido de {direccion}: {e}")
                continue

            flags = paquete.header.flags

            # 3. Enrutamiento por canales
            if direccion not in conexiones:
                # Es un cliente nuevo: solo se acepta si envía un paquete SYN para DOWNLOAD SACK
                if flags.syn and flags.operation == HeaderFlags.Operation.DOWNLOAD:
                    logging.info(f"[SERVIDOR] Nuevo cliente detectado: {direccion}. Creando canal e hilo trabajador...")
                    canal = Queue()
                    hilo = threading.Thread(
                        target=atender_cliente_download_sack,
                        args=(sock, direccion, canal, directorio_almacenamiento, stop_event),
                        daemon=True
                    )
                    conexiones[direccion] = (canal, hilo)
                    hilo.start()
                    canal.put(paquete)
                else:
                    logging.debug(f"[SERVIDOR] Paquete ignorado de {direccion} (no es SYN DOWNLOAD inicial): {paquete}")
            else:
                # El cliente ya tiene un hilo asignado: derivamos el paquete a su canal correspondiente
                conexiones[direccion][0].put(paquete)

    except KeyboardInterrupt:
        logging.info("[SERVIDOR SACK DOWNLOAD] Interrupción por teclado (Ctrl+C). Finalizando servidor...")

    finally:
        stop_event.set()
        logging.info(f"[SERVIDOR] Esperando finalización de {len(conexiones)} conexiones activas...")
        for direccion, (_, hilo) in conexiones.items():
            hilo.join(timeout=2.0)
        sock.close()
        logging.info("[SERVIDOR SACK DOWNLOAD] Socket cerrado. Servidor apagado.")


def main():
    args = server_parse_args()
    logging.basicConfig(
        level=max(logging.DEBUG, min(logging.CRITICAL, logging.WARNING + 10 * (args.quiet - args.verbose))),
        format="%(levelname)s: %(message)s"
    )
    servidor_sack_download(args.host, args.port, args.storage)


if __name__ == "__main__":
    main()
