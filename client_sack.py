import os
import sys
import time
import socket
import logging
import argparse

from protocolo import (
    HEADER_SIZE,
    MAX_PAYLOAD,
    MTU,
    ERR_NONE,
    ERRORES_DESC,
    Packet,
    HeaderFlags,
    SequenceNumber,
    MessageSynUpload,
)
from sack import (
    EmisorSack,
    ReceptorSack,
    ejecutar_cierre_emisor,
    ejecutar_cierre_receptor,
)


def download_sack(nombre_archivo: str, direccion_ip: str, puerto: int, ruta_destino: str | None = None):
    """Descarga un archivo desde el servidor utilizando el protocolo SACK."""
    if ruta_destino is None:
        ruta_destino = nombre_archivo

    servidor_addr = (direccion_ip, puerto)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # 1. Handshake de sincronización para DOWNLOAD (Stop and Wait)
        secuencia_syn = 1
        paquete_syn = Packet(
            sequence_number=secuencia_syn,
            ack_number=0,
            flags=HeaderFlags(
                type=HeaderFlags.Type.SACK,
                operation=HeaderFlags.Operation.DOWNLOAD,
                ack=False,
                syn=True,
                fin=False,
                error=ERR_NONE
            ),
            payload=nombre_archivo.encode()
        )

        timeout = 1.0
        intentos = 0
        max_intentos = 5
        primer_paquete_datos = None
        siguiente_sn_receptor = None
        sn_esperado_emisor = None

        while intentos < max_intentos:
            sock.settimeout(timeout)
            try:
                logging.debug(f"[CLIENTE SACK DOWNLOAD] Enviando SYN a {servidor_addr} (intento {intentos + 1}/{max_intentos})")
                sock.sendto(paquete_syn.serialize(), servidor_addr)

                while True:
                    datos, addr = sock.recvfrom(MTU)
                    respuesta = Packet.deserialize(datos)
                    flags = respuesta.header.flags

                    if flags.error != ERR_NONE:
                        desc = ERRORES_DESC.get(flags.error, f"Error {flags.error}")
                        raise RuntimeError(f"El servidor rechazó la descarga ({flags.error}): {desc}")

                    if flags.syn and flags.ack and respuesta.header.ack_number == secuencia_syn:
                        seq_servidor = respuesta.header.sequence_number
                        sn_esperado_emisor = SequenceNumber.next_seq(seq_servidor)

                        # Enviar ACK al SYN-ACK
                        sn_number_receptor = SequenceNumber.next_seq(secuencia_syn)  # 2
                        paquete_ack = Packet(
                            sequence_number=sn_number_receptor,
                            ack_number=seq_servidor,
                            flags=HeaderFlags(
                                type=HeaderFlags.Type.SACK,
                                operation=HeaderFlags.Operation.DOWNLOAD,
                                ack=True,
                                syn=False,
                                fin=False,
                                error=ERR_NONE
                            )
                        )
                        sock.sendto(paquete_ack.serialize(), addr)
                        siguiente_sn_receptor = SequenceNumber.next_seq(sn_number_receptor)  # 3

                        # Esperar primer bloque de datos
                        t_datos = timeout
                        for _ in range(max_intentos):
                            sock.settimeout(t_datos)
                            try:
                                d_sig, _ = sock.recvfrom(MTU)
                                p_sig = Packet.deserialize(d_sig)
                                if p_sig.header.flags.syn and p_sig.header.flags.ack:
                                    sock.sendto(paquete_ack.serialize(), addr)
                                    t_datos *= 2
                                    continue
                                primer_paquete_datos = p_sig
                                break
                            except socket.timeout:
                                sock.sendto(paquete_ack.serialize(), addr)
                                t_datos *= 2

                        break
                if siguiente_sn_receptor is not None:
                    break

            except socket.timeout:
                intentos += 1
                timeout *= 2

        if siguiente_sn_receptor is None:
            raise TimeoutError("[CLIENTE SACK DOWNLOAD] No se pudo establecer conexión con el servidor.")

        # 2. Recepción de datos con ReceptorSack
        logging.info(f"[CLIENTE SACK DOWNLOAD] Recibiendo '{nombre_archivo}' y guardando en '{ruta_destino}'...")
        with open(ruta_destino, "wb") as archivo:
            def enviar_ack(pkt: Packet):
                sock.sendto(pkt.serialize(), servidor_addr)

            def recibir_pkt() -> Packet | None:
                sock.settimeout(10.0)
                try:
                    raw, _ = sock.recvfrom(MTU)
                    return Packet.deserialize(raw)
                except socket.timeout:
                    return None

            receptor = ReceptorSack(
                archivo_abierto=archivo,
                secuencia_esperada_inicial=sn_esperado_emisor,
                secuencia_ack_inicial=siguiente_sn_receptor,
                operation=HeaderFlags.Operation.DOWNLOAD,
                enviar_ack_fn=enviar_ack,
                recibir_pkt_fn=recibir_pkt
            )
            pkt_fin, siguiente_sn_ack, _ = receptor.recibir_hasta_fin(primer_paquete=primer_paquete_datos)

        # 3. Cierre de conexión Four-Way Handshake (como Receptor)
        def enviar_fin(pkt: Packet):
            sock.sendto(pkt.serialize(), servidor_addr)

        def recibir_fin() -> Packet | None:
            sock.settimeout(1.0)
            try:
                raw, _ = sock.recvfrom(MTU)
                return Packet.deserialize(raw)
            except socket.timeout:
                return None

        ejecutar_cierre_receptor(
            paquete_fin_emisor=pkt_fin,
            seq_cliente_ack=siguiente_sn_ack,
            operation=HeaderFlags.Operation.DOWNLOAD,
            enviar_fn=enviar_fin,
            recibir_fn=recibir_fin
        )
        logging.info(f"[CLIENTE SACK DOWNLOAD] Descarga de '{nombre_archivo}' finalizada con éxito.")

    finally:
        sock.close()


def upload_sack(ruta_origen: str, direccion_ip: str, puerto: int, nombre_destino: str | None = None):
    """Sube un archivo hacia el servidor utilizando el protocolo SACK."""
    if not os.path.isfile(ruta_origen):
        raise FileNotFoundError(f"El archivo local '{ruta_origen}' no existe.")

    if nombre_destino is None:
        nombre_destino = os.path.basename(ruta_origen)

    servidor_addr = (direccion_ip, puerto)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # 1. Handshake de sincronización para UPLOAD (Stop and Wait)
        tamano_archivo = os.path.getsize(ruta_origen)
        secuencia_syn = 1
        payload_syn = MessageSynUpload(file_size=tamano_archivo, file_name=nombre_destino).serialize()

        paquete_syn = Packet(
            sequence_number=secuencia_syn,
            ack_number=0,
            flags=HeaderFlags(
                type=HeaderFlags.Type.SACK,
                operation=HeaderFlags.Operation.UPLOAD,
                ack=False,
                syn=True,
                fin=False,
                error=ERR_NONE
            ),
            payload=payload_syn
        )

        timeout = 1.0
        intentos = 0
        max_intentos = 5
        siguiente_seq_cliente = None

        while intentos < max_intentos:
            sock.settimeout(timeout)
            try:
                logging.debug(f"[CLIENTE SACK UPLOAD] Enviando SYN a {servidor_addr} (intento {intentos + 1}/{max_intentos})")
                sock.sendto(paquete_syn.serialize(), servidor_addr)

                while True:
                    datos, addr = sock.recvfrom(MTU)
                    respuesta = Packet.deserialize(datos)
                    flags = respuesta.header.flags

                    if flags.error != ERR_NONE:
                        desc = ERRORES_DESC.get(flags.error, f"Error {flags.error}")
                        raise RuntimeError(f"El servidor rechazó la subida ({flags.error}): {desc}")

                    if flags.syn and flags.ack and respuesta.header.ack_number == secuencia_syn:
                        seq_servidor = respuesta.header.sequence_number

                        # Enviar ACK al SYN-ACK
                        sn_ack = SequenceNumber.next_seq(secuencia_syn)  # 2
                        paquete_ack = Packet(
                            sequence_number=sn_ack,
                            ack_number=seq_servidor,
                            flags=HeaderFlags(
                                type=HeaderFlags.Type.SACK,
                                operation=HeaderFlags.Operation.UPLOAD,
                                ack=True,
                                syn=False,
                                fin=False,
                                error=ERR_NONE
                            )
                        )
                        sock.sendto(paquete_ack.serialize(), addr)
                        siguiente_seq_cliente = SequenceNumber.next_seq(sn_ack)  # 3
                        break

                if siguiente_seq_cliente is not None:
                    break

            except socket.timeout:
                intentos += 1
                timeout *= 2

        if siguiente_seq_cliente is None:
            raise TimeoutError("[CLIENTE SACK UPLOAD] No se pudo establecer conexión con el servidor.")

        # 2. Envío de datos con EmisorSack
        with open(ruta_origen, "rb") as f:
            contenido = f.read()

        bloques = [contenido[i:i + MAX_PAYLOAD] for i in range(0, len(contenido), MAX_PAYLOAD)] if contenido else [b""]
        logging.info(f"[CLIENTE SACK UPLOAD] Subiendo '{ruta_origen}' ({len(contenido)} bytes en {len(bloques)} bloques)...")

        def enviar_pkt(pkt: Packet):
            sock.sendto(pkt.serialize(), servidor_addr)

        def recibir_ack() -> Packet | None:
            sock.settimeout(0.03)
            try:
                raw, _ = sock.recvfrom(MTU)
                return Packet.deserialize(raw)
            except socket.timeout:
                return None

        emisor = EmisorSack(
            bloques=bloques,
            secuencia_inicial=siguiente_seq_cliente,
            operation=HeaderFlags.Operation.UPLOAD,
            enviar_pkt_fn=enviar_pkt,
            recibir_ack_fn=recibir_ack
        )
        seq_fin_cliente = emisor.transmitir()

        # 3. Cierre Four-Way Handshake (como Emisor)
        def enviar_fin(pkt: Packet):
            sock.sendto(pkt.serialize(), servidor_addr)

        def recibir_fin() -> Packet | None:
            sock.settimeout(1.0)
            try:
                raw, _ = sock.recvfrom(MTU)
                return Packet.deserialize(raw)
            except socket.timeout:
                return None

        ejecutar_cierre_emisor(
            seq_fin_emisor=seq_fin_cliente,
            operation=HeaderFlags.Operation.UPLOAD,
            enviar_fn=enviar_fin,
            recibir_fn=recibir_fin
        )
        logging.info(f"[CLIENTE SACK UPLOAD] Subida de '{ruta_origen}' finalizada con éxito.")

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="Cliente unificado SACK (Upload / Download)")
    subparsers = parser.add_subparsers(dest="comando", required=True, help="Operación a realizar")

    # Subcomando download
    parser_down = subparsers.add_parser("download", help="Descargar un archivo del servidor")
    parser_down.add_argument("archivo", nargs="?", default=None, help="Nombre del archivo a descargar")
    parser_down.add_argument("-n", "--name", dest="name_opt", default=None, help="Nombre del archivo a descargar en el servidor")
    parser_down.add_argument("-d", "--dst", default=None, help="Ruta de destino local")
    parser_down.add_argument("-H", "--host", default="127.0.0.1", help="IP del servidor (default: 127.0.0.1)")
    parser_down.add_argument("-p", "--port", type=int, default=12345, help="Puerto del servidor (default: 12345)")
    parser_down.add_argument("-v", "--verbose", action="store_true", help="Logs detallados")
    parser_down.add_argument("-q", "--quiet", action="store_true", help="Reducir logs")

    # Subcomando upload
    parser_up = subparsers.add_parser("upload", help="Subir un archivo al servidor")
    parser_up.add_argument("src", nargs="?", default=None, help="Ruta del archivo local a subir")
    parser_up.add_argument("-s", "--src", dest="src_opt", default=None, help="Ruta del archivo local a subir")
    parser_up.add_argument("-n", "--name", default=None, help="Nombre de destino en el servidor")
    parser_up.add_argument("-H", "--host", default="127.0.0.1", help="IP del servidor (default: 127.0.0.1)")
    parser_up.add_argument("-p", "--port", type=int, default=12345, help="Puerto del servidor (default: 12345)")
    parser_up.add_argument("-v", "--verbose", action="store_true", help="Logs detallados")
    parser_up.add_argument("-q", "--quiet", action="store_true", help="Reducir logs")

    args = parser.parse_args()

    nivel_log = logging.INFO
    if args.verbose:
        nivel_log = logging.DEBUG
    elif args.quiet:
        nivel_log = logging.WARNING

    logging.basicConfig(level=nivel_log, format="%(levelname)s: %(message)s")

    if args.comando == "download":
        archivo_objetivo = args.archivo or args.name_opt
        if not archivo_objetivo:
            parser_down.error("Debe especificar el nombre del archivo a descargar (posicional o -n/--name).")
        download_sack(archivo_objetivo, args.host, args.port, args.dst)
    elif args.comando == "upload":
        archivo_origen = args.src or args.src_opt
        if not archivo_origen:
            parser_up.error("Debe especificar la ruta del archivo a subir (posicional o -s/--src).")
        upload_sack(archivo_origen, args.host, args.port, args.name)


if __name__ == "__main__":
    main()
