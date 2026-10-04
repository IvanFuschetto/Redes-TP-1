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
    SackPayload,
    MessageSynUpload,
)


def crear_paquete_datos_upload(sequence_number: int, payload: bytes) -> Packet:
    """Crea un paquete de datos para la operación UPLOAD con protocolo SACK."""
    flags = HeaderFlags(
        type=HeaderFlags.Type.SACK,
        operation=HeaderFlags.Operation.UPLOAD,
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


def iniciar_handshake_upload(
    sock: socket.socket,
    direccion_ip: str,
    puerto: int,
    ruta_origen: str,
    nombre_destino: str
) -> tuple[int, int]:
    """
    Inicia el handshake de sincronización para la subida (Stop and Wait):
      1. Envía SYN con MessageSynUpload (tamaño del archivo y nombre).
      2. Espera SYN-ACK del servidor con backoff exponencial.
      3. Responde con ACK al SYN-ACK del servidor.
    Retorna: (siguiente_seq_cliente, seq_esperado_servidor)
    """
    servidor_addr = (direccion_ip, puerto)
    tamano_archivo = os.path.getsize(ruta_origen)
    secuencia_syn = 1
    timeout = 1.0
    timeout_cont = 0
    max_intentos = 5

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

    while timeout_cont < max_intentos:
        sock.settimeout(timeout)
        try:
            logging.debug(f"[CLIENTE UPLOAD] Enviando SYN a {servidor_addr} (intento {timeout_cont + 1}/{max_intentos})")
            sock.sendto(paquete_syn.serialize(), servidor_addr)

            while True:
                datos, addr = sock.recvfrom(MTU)
                respuesta = Packet.deserialize(datos)
                flags = respuesta.header.flags

                # Verificar si el servidor rechazó la subida (ej. archivo ya existe, tamaño excedido)
                if flags.error != ERR_NONE:
                    desc = ERRORES_DESC.get(flags.error, f"Error {flags.error}")
                    logging.error(f"[CLIENTE UPLOAD] El servidor rechazó la subida ({flags.error}): {desc}")
                    raise RuntimeError(f"El servidor rechazó la subida ({flags.error}): {desc}")

                # Cuando llega el SYN-ACK correspondiente
                if flags.syn and flags.ack and respuesta.header.ack_number == secuencia_syn:
                    seq_servidor = respuesta.header.sequence_number
                    sn_esperado_servidor = SequenceNumber.next_seq(seq_servidor)

                    logging.info(f"[CLIENTE UPLOAD] SYN-ACK recibido de {addr}. SEQ servidor={seq_servidor}")

                    # Responder con ACK al SYN-ACK del servidor
                    sn_ack_cliente = SequenceNumber.next_seq(secuencia_syn)  # 2
                    paquete_ack = Packet(
                        sequence_number=sn_ack_cliente,
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

                    siguiente_seq_cliente = SequenceNumber.next_seq(sn_ack_cliente)  # 3
                    return siguiente_seq_cliente, sn_esperado_servidor

        except socket.timeout:
            logging.debug("[CLIENTE UPLOAD] Timeout en SYN. Duplicando tiempo de espera.")
            timeout_cont += 1
            timeout *= 2

    raise TimeoutError("[CLIENTE UPLOAD] Demasiados timeouts al iniciar handshake de subida.")


def enviar_datos_sack_upload(
    sock: socket.socket,
    direccion_ip: str,
    puerto: int,
    ruta_origen: str,
    seq_inicial_cliente: int,
    tamano_ventana: int = 16,
    timeout_retransmision: float = 0.4
) -> int:
    """
    Envía el contenido del archivo al servidor utilizando ventana deslizante y SACK:
      - Envía ráfagas dentro de la ventana de transmisión.
      - Procesa confirmaciones acumulativas y bloques SACK.
      - Retransmite únicamente los paquetes que sufrieron timeout y no fueron recibidos por SACK.
    Retorna: el siguiente número de secuencia del cliente para el FIN.
    """
    servidor_addr = (direccion_ip, puerto)

    # Cargar archivo y dividir en bloques de MAX_PAYLOAD bytes
    with open(ruta_origen, "rb") as f:
        contenido = f.read()

    bloques = [contenido[i:i + MAX_PAYLOAD] for i in range(0, len(contenido), MAX_PAYLOAD)] if contenido else [b""]
    total_bloques = len(bloques)

    base_seq = seq_inicial_cliente
    proximo_seq = base_seq
    indice_bloque = 0

    paquetes_no_confirmados: dict[int, tuple[Packet, float]] = {}  # seq -> (paquete, timestamp_envio)
    bloques_recibidos_por_sack: set[int] = set()

    logging.info(f"[CLIENTE UPLOAD] Iniciando transmisión de {total_bloques} bloques ({len(contenido)} bytes)...")

    # Bucle principal de envío y recepción de ACKs
    while indice_bloque < total_bloques or paquetes_no_confirmados:
        # 1. Enviar paquetes mientras la ventana activa lo permita
        while indice_bloque < total_bloques and SequenceNumber.is_in_window(proximo_seq, base_seq, tamano_ventana):
            paquete = crear_paquete_datos_upload(proximo_seq, bloques[indice_bloque])
            sock.sendto(paquete.serialize(), servidor_addr)
            paquetes_no_confirmados[proximo_seq] = (paquete, time.monotonic())

            proximo_seq = SequenceNumber.next_seq(proximo_seq)
            indice_bloque += 1

        # 2. Recibir confirmaciones ACK/SACK del servidor con timeout corto
        sock.settimeout(0.03)
        try:
            datos_ack, _ = sock.recvfrom(MTU)
            paquete_ack = Packet.deserialize(datos_ack)
            flags = paquete_ack.header.flags

            if flags.error != ERR_NONE:
                desc = ERRORES_DESC.get(flags.error, f"Error {flags.error}")
                raise RuntimeError(f"El servidor reportó un error durante la subida ({flags.error}): {desc}")

            if flags.ack:
                ack_acumulativo = paquete_ack.header.ack_number

                # 2.1 Procesar bloques SACK presentes en el payload
                if paquete_ack.payload:
                    sack_payload = SackPayload.deserialize(paquete_ack.payload)
                    for inicio, fin in sack_payload.blocks:
                        curr = inicio
                        for _ in range(256):
                            bloques_recibidos_por_sack.add(curr)
                            if curr == fin:
                                break
                            curr = SequenceNumber.next_seq(curr)

                # 2.2 Deslizar la ventana acumulativa
                if paquetes_no_confirmados and SequenceNumber.is_in_window(ack_acumulativo, base_seq, tamano_ventana):
                    curr_base = base_seq
                    for _ in range(256):
                        paquetes_no_confirmados.pop(curr_base, None)
                        bloques_recibidos_por_sack.discard(curr_base)
                        if curr_base == ack_acumulativo:
                            break
                        curr_base = SequenceNumber.next_seq(curr_base)
                    base_seq = SequenceNumber.next_seq(ack_acumulativo)

        except socket.timeout:
            pass

        # 3. Retransmitir por timeout individual paquetes no confirmados ni en SACK
        ahora = time.monotonic()
        for seq_num, (pkt_guardado, timestamp_envio) in list(paquetes_no_confirmados.items()):
            if seq_num not in bloques_recibidos_por_sack and (ahora - timestamp_envio) > timeout_retransmision:
                logging.debug(f"[CLIENTE UPLOAD] Retransmitiendo paquete SEQ={seq_num}")
                sock.sendto(pkt_guardado.serialize(), servidor_addr)
                paquetes_no_confirmados[seq_num] = (pkt_guardado, ahora)

    logging.info("[CLIENTE UPLOAD] Todos los bloques de datos fueron enviados y confirmados exitosamente.")
    return proximo_seq


def finalizar_handshake_fin_upload(
    sock: socket.socket,
    direccion_ip: str,
    puerto: int,
    seq_fin_cliente: int,
    timeout_inicial: float = 1.0,
    max_intentos: int = 5
):
    """
    Ejecuta el Four-Way Handshake de cierre cuando el cliente termina el UPLOAD:
      - Paso 1: El cliente envía su FIN (seq_fin_cliente).
      - Paso 2: El cliente espera el ACK del servidor confirmando su FIN.
      - Paso 3: El cliente espera el FIN del servidor.
      - Paso 4: El cliente responde con ACK al FIN del servidor.
    """
    servidor_addr = (direccion_ip, puerto)
    timeout = timeout_inicial
    timeout_cont = 0

    # Paso 1: Paquete FIN propio del cliente
    paquete_fin_cliente = Packet(
        sequence_number=seq_fin_cliente,
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

    ack_paso2_recibido = False
    paquete_fin_servidor = None

    # Enviar FIN del cliente y esperar confirmación (Pasos 1 y 2)
    while timeout_cont < max_intentos:
        sock.settimeout(timeout)
        try:
            logging.debug(f"[CLIENTE UPLOAD] Enviando FIN con SEQ={seq_fin_cliente} a {servidor_addr} (intento {timeout_cont + 1}/{max_intentos})")
            sock.sendto(paquete_fin_cliente.serialize(), servidor_addr)

            while True:
                datos, addr = sock.recvfrom(MTU)
                respuesta = Packet.deserialize(datos)
                flags = respuesta.header.flags

                # Paso 2: El servidor confirmó el FIN del cliente
                if flags.ack and not flags.fin and respuesta.header.ack_number == seq_fin_cliente:
                    logging.info("[CLIENTE UPLOAD] ACK del FIN del cliente recibido del servidor (Paso 2).")
                    ack_paso2_recibido = True
                    break

                # Si el servidor ya mandó su propio FIN (Paso 3) directamente
                if flags.fin and not flags.ack:
                    paquete_fin_servidor = respuesta
                    ack_paso2_recibido = True
                    break

            if ack_paso2_recibido:
                break

        except socket.timeout:
            timeout_cont += 1
            timeout *= 2

    if not ack_paso2_recibido:
        logging.warning("[CLIENTE UPLOAD] Timeout esperando ACK al FIN del cliente.")

    # Paso 3: Esperar FIN del servidor si no llegó todavía
    if paquete_fin_servidor is None:
        sock.settimeout(5.0)
        try:
            while True:
                datos, addr = sock.recvfrom(MTU)
                respuesta = Packet.deserialize(datos)
                if respuesta.header.flags.fin and not respuesta.header.flags.ack:
                    paquete_fin_servidor = respuesta
                    logging.info(f"[CLIENTE UPLOAD] FIN del servidor recibido con SEQ={respuesta.header.sequence_number} (Paso 3).")
                    break
        except socket.timeout:
            logging.warning("[CLIENTE UPLOAD] Timeout esperando FIN del servidor.")

    # Paso 4: Responder con ACK al FIN del servidor
    if paquete_fin_servidor is not None:
        seq_ack_cierre = SequenceNumber.next_seq(seq_fin_cliente)
        paquete_ack_final = Packet(
            sequence_number=seq_ack_cierre,
            ack_number=paquete_fin_servidor.header.sequence_number,
            flags=HeaderFlags(
                type=HeaderFlags.Type.SACK,
                operation=HeaderFlags.Operation.UPLOAD,
                ack=True,
                syn=False,
                fin=False,
                error=ERR_NONE
            )
        )
        # Enviamos dos veces para tolerar pérdidas del último paquete
        sock.sendto(paquete_ack_final.serialize(), servidor_addr)
        sock.sendto(paquete_ack_final.serialize(), servidor_addr)
        logging.info("[CLIENTE UPLOAD] ACK final enviado (Paso 4). Handshake de cierre completado con éxito.")


def upload_sack(ruta_origen: str, direccion_ip: str, puerto: int, nombre_destino: str | None = None):
    """
    Coordina la subida completa de un archivo hacia el servidor usando SACK:
      1. Abre el socket UDP.
      2. Inicia el handshake de sincronización (SYN UPLOAD con MessageSynUpload).
      3. Transmite todos los bloques con ventana deslizante y SACK.
      4. Cierra la conexión mediante el Four-Way Handshake.
    """
    if not os.path.isfile(ruta_origen):
        raise FileNotFoundError(f"El archivo local '{ruta_origen}' no existe.")

    if nombre_destino is None:
        nombre_destino = os.path.basename(ruta_origen)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 1. Handshake de inicio
        seq_inicial_datos, _ = iniciar_handshake_upload(
            sock, direccion_ip, puerto, ruta_origen, nombre_destino
        )

        # 2. Envío de datos con ventana deslizante y SACK
        seq_fin_cliente = enviar_datos_sack_upload(
            sock, direccion_ip, puerto, ruta_origen, seq_inicial_datos
        )

        # 3. Cierre ordenado Four-Way Handshake
        finalizar_handshake_fin_upload(
            sock, direccion_ip, puerto, seq_fin_cliente
        )

        logging.info(f"[CLIENTE UPLOAD] Subida de '{ruta_origen}' a '{nombre_destino}' completada con éxito.")

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="Cliente para subida de archivos mediante SACK")
    parser.add_argument("src", help="Ruta del archivo local a subir")
    parser.add_argument("-H", "--host", default="127.0.0.1", help="Dirección IP del servidor (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=12345, help="Puerto UDP del servidor (default: 12345)")
    parser.add_argument("-n", "--name", default=None, help="Nombre del archivo en el destino")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostrar logs detallados")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s"
    )
    upload_sack(args.src, args.host, args.port, args.name)


if __name__ == "__main__":
    main()
