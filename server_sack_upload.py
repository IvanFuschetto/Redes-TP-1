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
    ERR_FILE_EXISTS,
    ERR_FILE_TOO_BIG,
    ERRORES_DESC,
    Packet,
    HeaderFlags,
    SequenceNumber,
    SackPayload,
    MessageSynUpload,
    compute_sack_blocks,
)
from parser import server_parse_args

MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MiB


def atender_cliente_upload_sack(
    sock: socket.socket,
    direccion_cliente: tuple[str, int],
    canal_paquetes: Queue,
    directorio_almacenamiento: str,
    stop_event: threading.Event
):
    """
    Hilo trabajador encargado de gestionar la sesión de subida completa para un cliente específico:
      1. Fase de Handshake (SYN -> SYN-ACK -> ACK) con validación de MessageSynUpload.
      2. Fase de Recepción de Datos con SACK y almacenamiento en disco.
      3. Fase de Cierre con Four-Way Handshake (Stop and Wait).
    """
    logging.info(f"[SERVIDOR UPLOAD SACK] Atendiendo cliente {direccion_cliente}")
    archivo_abierto = None

    try:
        # -------------------------------------------------------------
        # 1. FASE DE HANDSHAKE (SYN / SYN-ACK / ACK)
        # -------------------------------------------------------------
        try:
            paquete_syn: Packet = canal_paquetes.get(timeout=5.0)
        except Empty:
            logging.warning(f"[SERVIDOR UPLOAD] Timeout esperando SYN de {direccion_cliente}.")
            return

        try:
            mensaje_syn = MessageSynUpload.deserialize(paquete_syn.payload)
            tamano_archivo = mensaje_syn.file_size
            nombre_archivo = mensaje_syn.file_name
        except Exception as e:
            logging.error(f"[SERVIDOR UPLOAD] Payload SYN inválido de {direccion_cliente}: {e}")
            return

        ruta_archivo = os.path.join(directorio_almacenamiento, nombre_archivo)
        logging.info(f"[SERVIDOR UPLOAD] Cliente {direccion_cliente} desea subir '{nombre_archivo}' ({tamano_archivo} bytes)")

        # Validaciones de subida
        error_subida = ERR_NONE
        if tamano_archivo > MAX_FILE_SIZE:
            error_subida = ERR_FILE_TOO_BIG
            logging.warning(f"[SERVIDOR UPLOAD] Archivo demasiado grande: {tamano_archivo} > {MAX_FILE_SIZE}")
        elif os.path.exists(ruta_archivo):
            error_subida = ERR_FILE_EXISTS
            logging.warning(f"[SERVIDOR UPLOAD] El archivo ya existe: '{ruta_archivo}'")

        seq_servidor = 1
        paquete_syn_ack = Packet(
            sequence_number=seq_servidor,
            ack_number=paquete_syn.header.sequence_number,
            flags=HeaderFlags(
                type=HeaderFlags.Type.SACK,
                operation=HeaderFlags.Operation.UPLOAD,
                ack=True,
                syn=True,
                fin=False,
                error=error_subida
            )
        )

        # Si hubo error, notificamos al cliente y abortamos
        if error_subida != ERR_NONE:
            sock.sendto(paquete_syn_ack.serialize(), direccion_cliente)
            return

        # Abrir archivo para escritura
        archivo_abierto = open(ruta_archivo, "wb")

        # Handshake Stop and Wait: enviar SYN-ACK y esperar confirmación
        timeout_syn_ack = 1.0
        intentos = 0
        max_intentos = 5
        handshake_listo = False
        primer_paquete_datos = None

        while intentos < max_intentos and not stop_event.is_set():
            sock.sendto(paquete_syn_ack.serialize(), direccion_cliente)
            try:
                paquete_resp: Packet = canal_paquetes.get(timeout=timeout_syn_ack)
                flags_resp = paquete_resp.header.flags

                # Si es retransmisión de SYN, reenviar SYN-ACK
                if flags_resp.syn and not flags_resp.ack:
                    continue

                # El cliente confirmó con ACK
                if flags_resp.ack and not flags_resp.syn and paquete_resp.header.ack_number == seq_servidor:
                    logging.info(f"[SERVIDOR UPLOAD] Handshake de inicio completado con {direccion_cliente}.")
                    handshake_listo = True
                    break

                # O el cliente ya mandó directamente el primer bloque de datos
                if not flags_resp.syn and not flags_resp.ack and not flags_resp.fin:
                    primer_paquete_datos = paquete_resp
                    handshake_listo = True
                    break

            except Empty:
                intentos += 1
                timeout_syn_ack *= 2

        if not handshake_listo:
            logging.warning(f"[SERVIDOR UPLOAD] Timeout en handshake con {direccion_cliente}.")
            return

        # -------------------------------------------------------------
        # 2. FASE DE RECEPCIÓN DE DATOS CON SACK
        # -------------------------------------------------------------
        numero_secuencia_esperado = 3
        siguiente_sn_servidor = SequenceNumber.next_seq(seq_servidor)  # 2
        received_buffer = {}  # seq -> payload
        paquete_fin_cliente = None

        def procesar_bloque_recibido(paquete: Packet):
            nonlocal numero_secuencia_esperado, siguiente_sn_servidor, paquete_fin_cliente
            flags = paquete.header.flags

            if flags.fin:
                paquete_fin_cliente = paquete
                return True

            seq_num = paquete.header.sequence_number
            payload = paquete.payload or b""

            # En orden
            if seq_num == numero_secuencia_esperado:
                archivo_abierto.write(payload)
                numero_secuencia_esperado = SequenceNumber.next_seq(numero_secuencia_esperado)

                while numero_secuencia_esperado in received_buffer:
                    bloque = received_buffer.pop(numero_secuencia_esperado)
                    archivo_abierto.write(bloque)
                    numero_secuencia_esperado = SequenceNumber.next_seq(numero_secuencia_esperado)
            else:
                # Fuera de orden
                distancia = SequenceNumber.distance(seq_num, numero_secuencia_esperado)
                if 0 < distancia < 128:
                    if seq_num not in received_buffer:
                        received_buffer[seq_num] = payload

            # Calcular bloques SACK y enviar ACK
            sack_blocks = compute_sack_blocks(set(received_buffer.keys()), numero_secuencia_esperado)
            payload_sack = SackPayload(sack_blocks).serialize()
            ack_num = (numero_secuencia_esperado - 1) % 256

            paquete_ack = Packet(
                sequence_number=siguiente_sn_servidor,
                ack_number=ack_num,
                flags=HeaderFlags(
                    type=HeaderFlags.Type.SACK,
                    operation=HeaderFlags.Operation.UPLOAD,
                    ack=True,
                    syn=False,
                    fin=False,
                    error=ERR_NONE
                ),
                payload=payload_sack
            )
            sock.sendto(paquete_ack.serialize(), direccion_cliente)
            siguiente_sn_servidor = SequenceNumber.next_seq(siguiente_sn_servidor)
            return False

        # Si capturamos el primer bloque durante el handshake, procesarlo
        if primer_paquete_datos is not None:
            procesar_bloque_recibido(primer_paquete_datos)

        # Bucle de recepción de bloques
        while not stop_event.is_set():
            try:
                pkt: Packet = canal_paquetes.get(timeout=10.0)
                es_fin = procesar_bloque_recibido(pkt)
                if es_fin:
                    logging.info(f"[SERVIDOR UPLOAD] Paquete FIN recibido de {direccion_cliente}. Finalizando recepción...")
                    break
            except Empty:
                logging.warning(f"[SERVIDOR UPLOAD] Inactividad prolongada de {direccion_cliente}. Finalizando sesión.")
                break

        # Cerrar el archivo recibido
        if archivo_abierto is not None and not archivo_abierto.closed:
            archivo_abierto.close()

        if paquete_fin_cliente is None:
            logging.warning(f"[SERVIDOR UPLOAD] No se recibió el paquete FIN de {direccion_cliente}.")
            return

        # -------------------------------------------------------------
        # 3. FASE DE CIERRE: FOUR-WAY HANDSHAKE (STOP AND WAIT)
        # -------------------------------------------------------------
        # Paso 2: Servidor envía ACK al FIN del cliente
        paquete_ack_fin_cliente = Packet(
            sequence_number=siguiente_sn_servidor,
            ack_number=paquete_fin_cliente.header.sequence_number,
            flags=HeaderFlags(
                type=HeaderFlags.Type.SACK,
                operation=HeaderFlags.Operation.UPLOAD,
                ack=True,
                syn=False,
                fin=False,
                error=ERR_NONE
            )
        )
        sock.sendto(paquete_ack_fin_cliente.serialize(), direccion_cliente)
        logging.info(f"[SERVIDOR UPLOAD] ACK al FIN del cliente enviado (Paso 2) con SEQ={siguiente_sn_servidor}")

        # Paso 3: Servidor envía su propio FIN con Stop and Wait
        seq_fin_servidor = SequenceNumber.next_seq(siguiente_sn_servidor)
        paquete_fin_servidor = Packet(
            sequence_number=seq_fin_servidor,
            ack_number=0,
            flags=HeaderFlags(
                type=HeaderFlags.Type.SACK,
                operation=HeaderFlags.Operation.UPLOAD,
                ack=False,
                syn=False,
                fin=True,
                error=ERR_NONE
            )
        )

        timeout_cierre = 1.0
        intentos_cierre = 0
        while intentos_cierre < max_intentos and not stop_event.is_set():
            sock.sendto(paquete_fin_servidor.serialize(), direccion_cliente)
            try:
                resp_cierre: Packet = canal_paquetes.get(timeout=timeout_cierre)
                flags_c = resp_cierre.header.flags

                # Si el cliente retransmitió su FIN (porque perdió el ACK del Paso 2), le reenviamos el ACK
                if flags_c.fin and not flags_c.ack:
                    sock.sendto(paquete_ack_fin_cliente.serialize(), direccion_cliente)
                    continue

                # Paso 4: ACK del cliente confirmando el FIN del servidor
                if flags_c.ack and resp_cierre.header.ack_number == seq_fin_servidor:
                    logging.info(f"[SERVIDOR UPLOAD] ACK final recibido de {direccion_cliente}. Subida de '{nombre_archivo}' completada con éxito.")
                    return

            except Empty:
                intentos_cierre += 1
                timeout_cierre *= 2

        logging.warning(f"[SERVIDOR UPLOAD] Timeout esperando ACK final de {direccion_cliente}.")

    except Exception as e:
        logging.exception(f"[SERVIDOR UPLOAD] Error atendiendo a {direccion_cliente}: {e}")

    finally:
        if archivo_abierto is not None and not archivo_abierto.closed:
            archivo_abierto.close()
        logging.info(f"[SERVIDOR UPLOAD] Hilo para {direccion_cliente} finalizado.")


def servidor_sack_upload(
    host: str,
    port: int,
    directorio_almacenamiento: str,
    stop_event: threading.Event | None = None
):
    """
    Bucle principal del servidor SACK Upload:
      - Escucha en el socket UDP central.
      - Al recibir un SYN UPLOAD de una nueva dirección, crea una cola (Queue) y un hilo trabajador.
      - Enruta todos los paquetes subsiguientes de esa dirección al canal del hilo correspondiente.
      - Limpia periódicamente las conexiones finalizadas.
    """
    if stop_event is None:
        stop_event = threading.Event()

    if not os.path.isdir(directorio_almacenamiento):
        os.makedirs(directorio_almacenamiento, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(0.5)

    conexiones: dict[tuple[str, int], tuple[Queue, threading.Thread]] = {}

    logging.info(f"[SERVIDOR SACK UPLOAD] Escuchando en {host}:{port}")
    logging.info(f"[SERVIDOR SACK UPLOAD] Directorio de almacenamiento: '{directorio_almacenamiento}'")

    try:
        while not stop_event.is_set():
            # 1. Limpieza de hilos que ya terminaron su trabajo
            for direccion in list(conexiones.keys()):
                canal, hilo = conexiones[direccion]
                if not hilo.is_alive():
                    hilo.join()
                    del conexiones[direccion]
                    logging.debug(f"[SERVIDOR UPLOAD] Conexión de {direccion} cerrada y liberada.")

            # 2. Recepción de paquetes en el socket central
            try:
                datos, direccion = sock.recvfrom(MTU)
            except socket.timeout:
                continue

            try:
                paquete = Packet.deserialize(datos)
            except Exception as e:
                logging.warning(f"[SERVIDOR UPLOAD] Paquete corrupto de {direccion}: {e}")
                continue

            flags = paquete.header.flags

            # 3. Enrutamiento por canales
            if direccion not in conexiones:
                # Solo se acepta conexión nueva si envía SYN para UPLOAD SACK
                if flags.syn and flags.operation == HeaderFlags.Operation.UPLOAD:
                    logging.info(f"[SERVIDOR UPLOAD] Nuevo cliente detectado: {direccion}. Creando canal e hilo trabajador...")
                    canal = Queue()
                    hilo = threading.Thread(
                        target=atender_cliente_upload_sack,
                        args=(sock, direccion, canal, directorio_almacenamiento, stop_event),
                        daemon=True
                    )
                    conexiones[direccion] = (canal, hilo)
                    hilo.start()
                    canal.put(paquete)
                else:
                    logging.debug(f"[SERVIDOR UPLOAD] Paquete ignorado de {direccion} (no es SYN UPLOAD inicial): {paquete}")
            else:
                conexiones[direccion][0].put(paquete)

    except KeyboardInterrupt:
        logging.info("[SERVIDOR SACK UPLOAD] Interrupción por teclado (Ctrl+C). Finalizando servidor...")

    finally:
        stop_event.set()
        logging.info(f"[SERVIDOR UPLOAD] Esperando finalización de {len(conexiones)} conexiones activas...")
        for direccion, (_, hilo) in conexiones.items():
            hilo.join(timeout=2.0)
        sock.close()
        logging.info("[SERVIDOR SACK UPLOAD] Socket cerrado. Servidor apagado.")


def main():
    args = server_parse_args()
    logging.basicConfig(
        level=max(logging.DEBUG, min(logging.CRITICAL, logging.WARNING + 10 * (args.quiet - args.verbose))),
        format="%(levelname)s: %(message)s"
    )
    servidor_sack_upload(args.host, args.port, args.storage)


if __name__ == "__main__":
    main()
