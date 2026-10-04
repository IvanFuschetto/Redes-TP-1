import os
import sys
import time
import socket
import logging
import argparse
import threading
from queue import Queue, Empty

from protocolo import (
    HEADER_SIZE,
    MAX_PAYLOAD,
    MTU,
    ERR_NONE,
    ERR_INVALID_NAME,
    ERR_FILE_EXISTS,
    ERR_FILE_TOO_BIG,
    ERRORES_DESC,
    Packet,
    HeaderFlags,
    SequenceNumber,
    MessageSynUpload,
)
from sack import (
    MAX_FILE_SIZE,
    EmisorSack,
    ReceptorSack,
    ejecutar_cierre_emisor,
    ejecutar_cierre_receptor,
)


def atender_cliente_download_sack(
    sock: socket.socket,
    direccion_cliente: tuple[str, int],
    canal_paquetes: Queue,
    directorio_almacenamiento: str,
    stop_event: threading.Event
):
    """
    Hilo trabajador encargado de gestionar la sesión de descarga (DOWNLOAD) completa:
      1. Fase de Handshake (SYN -> SYN-ACK -> ACK) con Stop and Wait.
      2. Fase de Envío de Datos con EmisorSack (Ventana Deslizante + SACK).
      3. Fase de Cierre con Four-Way Handshake (como Emisor).
    """
    logging.info(f"[SERVIDOR DOWNLOAD SACK] Iniciando atención para {direccion_cliente}")

    try:
        # 1. Handshake de sincronización
        try:
            paquete_syn: Packet = canal_paquetes.get(timeout=5.0)
        except Empty:
            logging.warning(f"[SERVIDOR DOWNLOAD] Timeout esperando SYN de {direccion_cliente}. Abortando.")
            return

        nombre_archivo = paquete_syn.payload.decode(errors="ignore").strip()
        ruta_archivo = os.path.join(directorio_almacenamiento, nombre_archivo)
        logging.info(f"[SERVIDOR DOWNLOAD] Solicitud de '{nombre_archivo}' desde {direccion_cliente}")

        if not os.path.isfile(ruta_archivo):
            logging.error(f"[SERVIDOR DOWNLOAD] Archivo inexistente: '{ruta_archivo}'. Enviando error.")
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

        with open(ruta_archivo, "rb") as f:
            contenido = f.read()

        bloques = [contenido[i:i + MAX_PAYLOAD] for i in range(0, len(contenido), MAX_PAYLOAD)] if contenido else [b""]
        logging.info(f"[SERVIDOR DOWNLOAD] '{nombre_archivo}' ({len(contenido)} bytes) dividido en {len(bloques)} bloques.")

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
        intentos = 0
        max_intentos = 5
        handshake_ok = False

        while intentos < max_intentos and not stop_event.is_set():
            sock.sendto(paquete_syn_ack.serialize(), direccion_cliente)
            try:
                paquete_resp: Packet = canal_paquetes.get(timeout=timeout_syn_ack)
                flags_resp = paquete_resp.header.flags

                if flags_resp.syn and not flags_resp.ack:
                    continue

                if flags_resp.ack and not flags_resp.syn and paquete_resp.header.ack_number == seq_servidor:
                    logging.info(f"[SERVIDOR DOWNLOAD] Handshake completado con {direccion_cliente}.")
                    handshake_ok = True
                    break
            except Empty:
                intentos += 1
                timeout_syn_ack *= 2

        if not handshake_ok:
            logging.warning(f"[SERVIDOR DOWNLOAD] Handshake fallido con {direccion_cliente}. Cancelando sesión.")
            return

        # 2. Envío de datos utilizando EmisorSack
        def enviar_pkt(pkt: Packet):
            sock.sendto(pkt.serialize(), direccion_cliente)

        def recibir_ack() -> Packet | None:
            try:
                return canal_paquetes.get(timeout=0.03)
            except Empty:
                return None

        emisor = EmisorSack(
            bloques=bloques,
            secuencia_inicial=SequenceNumber.next_seq(seq_servidor),  # 2
            operation=HeaderFlags.Operation.DOWNLOAD,
            enviar_pkt_fn=enviar_pkt,
            recibir_ack_fn=recibir_ack,
            stop_event=stop_event
        )
        seq_fin_servidor = emisor.transmitir()

        # 3. Cierre de conexión Four-Way Handshake (como Emisor)
        def recibir_fin() -> Packet | None:
            try:
                return canal_paquetes.get(timeout=1.0)
            except Empty:
                return None

        ejecutar_cierre_emisor(
            seq_fin_emisor=seq_fin_servidor,
            operation=HeaderFlags.Operation.DOWNLOAD,
            enviar_fn=enviar_pkt,
            recibir_fn=recibir_fin
        )
        logging.info(f"[SERVIDOR DOWNLOAD] Transmisión exitosa hacia {direccion_cliente}.")

    except Exception as e:
        logging.exception(f"[SERVIDOR DOWNLOAD] Error atendiendo a {direccion_cliente}: {e}")


def atender_cliente_upload_sack(
    sock: socket.socket,
    direccion_cliente: tuple[str, int],
    canal_paquetes: Queue,
    directorio_almacenamiento: str,
    stop_event: threading.Event
):
    """
    Hilo trabajador encargado de gestionar la sesión de subida (UPLOAD) completa:
      1. Fase de Handshake (SYN -> SYN-ACK -> ACK) con validación de MessageSynUpload.
      2. Fase de Recepción de Datos con ReceptorSack (Reordenamiento + SACK).
      3. Fase de Cierre con Four-Way Handshake (como Receptor).
    """
    logging.info(f"[SERVIDOR UPLOAD SACK] Atendiendo cliente {direccion_cliente}")
    archivo_abierto = None

    try:
        # 1. Handshake de sincronización
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
        logging.info(f"[SERVIDOR UPLOAD] Cliente {direccion_cliente} sube '{nombre_archivo}' ({tamano_archivo} bytes)")

        error_subida = ERR_NONE
        if tamano_archivo > MAX_FILE_SIZE:
            error_subida = ERR_FILE_TOO_BIG
            logging.warning(f"[SERVIDOR UPLOAD] Archivo excede tamaño máximo: {tamano_archivo} > {MAX_FILE_SIZE}")
        elif os.path.exists(ruta_archivo):
            error_subida = ERR_FILE_EXISTS
            logging.warning(f"[SERVIDOR UPLOAD] Archivo ya existente: '{ruta_archivo}'")

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

        if error_subida != ERR_NONE:
            sock.sendto(paquete_syn_ack.serialize(), direccion_cliente)
            return

        archivo_abierto = open(ruta_archivo, "wb")

        timeout_syn_ack = 1.0
        intentos = 0
        max_intentos = 5
        handshake_ok = False
        primer_paquete_datos = None

        while intentos < max_intentos and not stop_event.is_set():
            sock.sendto(paquete_syn_ack.serialize(), direccion_cliente)
            try:
                paquete_resp: Packet = canal_paquetes.get(timeout=timeout_syn_ack)
                flags_resp = paquete_resp.header.flags

                if flags_resp.syn and not flags_resp.ack:
                    continue

                if flags_resp.ack and not flags_resp.syn and paquete_resp.header.ack_number == seq_servidor:
                    logging.info(f"[SERVIDOR UPLOAD] Handshake completado con {direccion_cliente}.")
                    handshake_ok = True
                    break

                if not flags_resp.syn and not flags_resp.ack and not flags_resp.fin:
                    primer_paquete_datos = paquete_resp
                    handshake_ok = True
                    break

            except Empty:
                intentos += 1
                timeout_syn_ack *= 2

        if not handshake_ok:
            logging.warning(f"[SERVIDOR UPLOAD] Timeout en handshake con {direccion_cliente}.")
            return

        # 2. Recepción de datos utilizando ReceptorSack
        def enviar_ack(pkt: Packet):
            sock.sendto(pkt.serialize(), direccion_cliente)

        def recibir_pkt() -> Packet | None:
            try:
                return canal_paquetes.get(timeout=0.2)
            except Empty:
                return None

        receptor = ReceptorSack(
            archivo_abierto=archivo_abierto,
            secuencia_esperada_inicial=3,
            secuencia_ack_inicial=SequenceNumber.next_seq(seq_servidor),  # 2
            operation=HeaderFlags.Operation.UPLOAD,
            enviar_ack_fn=enviar_ack,
            recibir_pkt_fn=recibir_pkt,
            stop_event=stop_event
        )
        pkt_fin, siguiente_sn_ack, _ = receptor.recibir_hasta_fin(primer_paquete=primer_paquete_datos)

        # Cerrar el archivo recibido
        if archivo_abierto is not None and not archivo_abierto.closed:
            archivo_abierto.close()

        # 3. Cierre Four-Way Handshake (como Receptor)
        def recibir_fin() -> Packet | None:
            try:
                return canal_paquetes.get(timeout=1.0)
            except Empty:
                return None

        ejecutar_cierre_receptor(
            paquete_fin_emisor=pkt_fin,
            seq_cliente_ack=siguiente_sn_ack,
            operation=HeaderFlags.Operation.UPLOAD,
            enviar_fn=enviar_ack,
            recibir_fn=recibir_fin
        )
        logging.info(f"[SERVIDOR UPLOAD] Recepción exitosa de '{nombre_archivo}' desde {direccion_cliente}.")

    except Exception as e:
        logging.exception(f"[SERVIDOR UPLOAD] Error atendiendo a {direccion_cliente}: {e}")
    finally:
        if archivo_abierto is not None and not archivo_abierto.closed:
            archivo_abierto.close()


def servidor_sack(
    host: str,
    port: int,
    directorio_almacenamiento: str,
    stop_event: threading.Event | None = None
):
    """
    Servidor UDP central unificado SACK (DOWNLOAD y UPLOAD):
      - Escucha paquetes entrantes en el socket principal.
      - Para cada nuevo cliente según su operación (DOWNLOAD o UPLOAD), crea un canal (Queue) y un hilo dedicado.
      - Despacha los paquetes entrantes al hilo correspondiente.
      - Limpia periódicamente hilos terminados.
    """
    if stop_event is None:
        stop_event = threading.Event()

    if not os.path.isdir(directorio_almacenamiento):
        os.makedirs(directorio_almacenamiento, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(0.5)

    conexiones: dict[tuple[str, int], tuple[Queue, threading.Thread]] = {}

    logging.info(f"[SERVIDOR SACK] Escuchando en {host}:{port}")
    logging.info(f"[SERVIDOR SACK] Directorio de almacenamiento: '{directorio_almacenamiento}'")

    try:
        while not stop_event.is_set():
            # 1. Limpieza de hilos finalizados
            for direccion in list(conexiones.keys()):
                canal, hilo = conexiones[direccion]
                if not hilo.is_alive():
                    hilo.join()
                    del conexiones[direccion]
                    logging.debug(f"[SERVIDOR SACK] Conexión de {direccion} finalizada y liberada.")

            # 2. Recepción de paquetes
            try:
                datos, direccion = sock.recvfrom(MTU)
            except socket.timeout:
                continue

            try:
                paquete = Packet.deserialize(datos)
            except Exception as e:
                logging.warning(f"[SERVIDOR SACK] Paquete corrupto recibido de {direccion}: {e}")
                continue

            flags = paquete.header.flags

            # 3. Enrutamiento y asignación de hilos
            if direccion not in conexiones:
                if flags.syn and flags.operation == HeaderFlags.Operation.DOWNLOAD:
                    logging.info(f"[SERVIDOR SACK] Nueva sesión DOWNLOAD desde {direccion}...")
                    canal = Queue()
                    hilo = threading.Thread(
                        target=atender_cliente_download_sack,
                        args=(sock, direccion, canal, directorio_almacenamiento, stop_event),
                        daemon=True
                    )
                    conexiones[direccion] = (canal, hilo)
                    hilo.start()
                    canal.put(paquete)
                elif flags.syn and flags.operation == HeaderFlags.Operation.UPLOAD:
                    logging.info(f"[SERVIDOR SACK] Nueva sesión UPLOAD desde {direccion}...")
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
                    logging.debug(f"[SERVIDOR SACK] Paquete no esperado de {direccion} sin sesión activa: {paquete}")
            else:
                conexiones[direccion][0].put(paquete)

    except KeyboardInterrupt:
        logging.info("[SERVIDOR SACK] Finalizando por Ctrl+C...")

    finally:
        stop_event.set()
        logging.info(f"[SERVIDOR SACK] Cerrando {len(conexiones)} conexiones activas...")
        for direccion, (_, hilo) in conexiones.items():
            hilo.join(timeout=2.0)
        sock.close()
        logging.info("[SERVIDOR SACK] Servidor detenido exitosamente.")


def main():
    parser = argparse.ArgumentParser(description="Servidor unificado SACK (Upload / Download)")
    parser.add_argument("-H", "--host", default="127.0.0.1", help="Dirección IP de escucha (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=12345, help="Puerto UDP (default: 12345)")
    parser.add_argument("-s", "--storage", default="storage", help="Directorio de almacenamiento (default: storage)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Logs detallados")
    parser.add_argument("-q", "--quiet", action="store_true", help="Reducir logs")

    args = parser.parse_args()

    nivel_log = logging.INFO
    if args.verbose:
        nivel_log = logging.DEBUG
    elif args.quiet:
        nivel_log = logging.WARNING

    logging.basicConfig(level=nivel_log, format="%(levelname)s: %(message)s")
    servidor_sack(args.host, args.port, args.storage)


if __name__ == "__main__":
    main()
