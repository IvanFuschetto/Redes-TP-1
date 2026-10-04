import socket
import os
import time
import logging

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
    compute_sack_blocks,
)


def calcular_bloques_sack(buffer: dict, expected_seq: int) -> list[tuple[int, int]]:
    """
    Analiza el búfer de paquetes desordenados y genera los bloques contiguos [start, end],
    respetando la aritmética circular módulo 256 a partir del número de secuencia esperado.
    """
    if not buffer:
        return []
    # Utilizamos la función de protocolo.py que agrupa y ordena según la distancia circular a expected_seq
    return compute_sack_blocks(set(buffer.keys()), expected_seq)


def crear_paquete_ack(ack_number: int, sack_blocks: list[tuple[int, int]], seq_cliente: int = 2) -> Packet:
    """
    Crea un paquete de confirmación (ACK) para la operación DOWNLOAD con SACK,
    incluyendo el número acumulativo de ACK y los bloques SACK en el payload.
    """
    payload_sack = SackPayload(sack_blocks).serialize()
    flags = HeaderFlags(
        type=HeaderFlags.Type.SACK,
        operation=HeaderFlags.Operation.DOWNLOAD,
        ack=True,
        syn=False,
        fin=False,
        error=ERR_NONE
    )
    return Packet(
        sequence_number=seq_cliente,
        ack_number=ack_number,
        flags=flags,
        payload=payload_sack
    )



def procesar_paquete_recibido(
    packet,
    received_buffer: dict,
    archivo_abierto,
    numero_secuencia_esperado_emisor: int,
    siguiente_sn_receptor: int,
    sock: socket.socket,
    addr: tuple
) -> tuple[int, int, bool, Packet | None]:
    """
    Procesa un paquete recibido:
      1. Desempaqueta y valida flags de error, FIN o SYN retransmitido.
      2. Si está en orden, escribe directamente en el archivo y vacía los paquetes bufferizados contiguos.
      3. Si está fuera de orden, lo guarda en received_buffer si se encuentra dentro de la ventana activa.
      4. Genera los bloques SACK y envía el ACK correspondiente al emisor utilizando sn_receptor.
      5. Avanza sn_receptor para la siguiente respuesta.
    Retorna: (expected_seq_actualizado, siguiente_sn_receptor, es_fin: bool, paquete_fin: Packet | None)
    """
    # 1. Desempaquetar el paquete recibido
    if isinstance(packet, bytes):
        packet = Packet.deserialize(packet)

    flags = packet.header.flags

    # Verificar si el servidor notificó alguna condición de error
    if flags.error != ERR_NONE:
        desc = ERRORES_DESC.get(flags.error, f"Error {flags.error}")
        logging.error(f"[CLIENTE DOWNLOAD] Error reportado por el servidor ({flags.error}): {desc}")
        raise RuntimeError(f"El servidor reportó un error ({flags.error}): {desc}")

    # Manejo de fin de transferencia (FIN recibido del servidor)
    if flags.fin:
        logging.info("[CLIENTE DOWNLOAD] Paquete FIN recibido del servidor. Finalizando recepción de datos para dar paso al handshake de cierre...")
        return numero_secuencia_esperado_emisor, siguiente_sn_receptor, True, packet

    seq_num_del_paquete = packet.header.sequence_number
    payload = packet.payload or b""
    proximo_numero_secuencia_esperado_emisor = numero_secuencia_esperado_emisor
    # 2. Guardar en el archivo o en el búfer según el número de secuencia
    if seq_num_del_paquete == numero_secuencia_esperado_emisor:
        # Paquete en orden: escribir de inmediato en el archivo
        archivo_abierto.write(payload)
        proximo_numero_secuencia_esperado_emisor = SequenceNumber.next_seq(numero_secuencia_esperado_emisor)

        # 3. Avanzar el ACK acumulativo y vaciar paquetes secuenciales disponibles en el búfer
        while proximo_numero_secuencia_esperado_emisor in received_buffer:
            bloque = received_buffer.pop(proximo_numero_secuencia_esperado_emisor)
            archivo_abierto.write(bloque)
            proximo_numero_secuencia_esperado_emisor = SequenceNumber.next_seq(proximo_numero_secuencia_esperado_emisor)
    else:
        # Paquete fuera de orden: verificar si cae en la ventana futura de recepción (hasta 127 posiciones)
        distancia = SequenceNumber.distance(seq_num_del_paquete, numero_secuencia_esperado_emisor)
        if 0 < distancia < 128:
            if seq_num_del_paquete not in received_buffer:
                received_buffer[seq_num_del_paquete] = payload
                logging.debug(f"[CLIENTE DOWNLOAD] Paquete desordenado SEQ={seq_num_del_paquete} almacenado en búfer.")

    # 4. Generar los bloques SACK
    sack_blocks = calcular_bloques_sack(received_buffer, proximo_numero_secuencia_esperado_emisor)

    # 5. Armar y enviar el paquete ACK de vuelta al emisor con sn_receptor
    # El ACK acumulativo confirma el último paquete continuo recibido (expected_seq - 1)
    ack_num = (proximo_numero_secuencia_esperado_emisor - 1) % 256
    ack_packet = crear_paquete_ack(ack_num, sack_blocks, seq_cliente=siguiente_sn_receptor)
    sock.sendto(ack_packet.serialize(), addr)

    # El sequence number avanza con cada ACK de respuesta enviado
    siguiente_sn_receptor = SequenceNumber.next_seq(siguiente_sn_receptor)

    return proximo_numero_secuencia_esperado_emisor, siguiente_sn_receptor, False, None



def iniciar_handshake(sock: socket.socket, direccion_ip: str, puerto: int, nombre_archivo: str) -> tuple[Packet,int, int]:
    """
    Inicia el handshake de sincronización para la descarga.
      - 5 intentos de Timeout con duplicación progresiva (backoff exponencial), iniciando en 1 segundo.
      - Envía SYN, SACK, DOWNLOAD con el nombre del archivo en el payload.
      - Espera el SYN-ACK del servidor.
      - Responde con ACK DOWNLOAD y aguarda el primer paquete de datos.
    Retorna: (primer_paquete_datos,siguiente_sn_receptor ,siguiente_sn_esperado_emisor)
    """
    servidor_addr = (direccion_ip, puerto)
    secuencia_syn = 1
    timeout = 1.0
    timeout_cont = 0
    max_intentos = 5

    # Crear paquete con flags: SYN, SACK, DOWNLOAD y en payload el nombre del archivo
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

    while timeout_cont < max_intentos:
        sock.settimeout(timeout)
        try:
            logging.debug(f"[CLIENTE DOWNLOAD] Enviando SYN a {servidor_addr} (intento {timeout_cont + 1}/{max_intentos}, timeout={timeout:.2f}s)")
            sock.sendto(paquete_syn.serialize(), servidor_addr)

            # Esperar SYN-ACK
            while True:
                datos, addr = sock.recvfrom(MTU)
                respuesta = Packet.deserialize(datos)
                flags = respuesta.header.flags

                # Verificar si el servidor notificó error de inicio
                if flags.error != ERR_NONE:
                    desc = ERRORES_DESC.get(flags.error, f"Error {flags.error}")
                    logging.error(f"[CLIENTE DOWNLOAD] El servidor rechazó la descarga ({flags.error}): {desc}")
                    raise RuntimeError(f"El servidor rechazó la descarga ({flags.error}): {desc}")

                # Cuando llega el SYN-ACK correspondiente
                if flags.syn and flags.ack and respuesta.header.ack_number == secuencia_syn:
                    seq_servidor = respuesta.header.sequence_number
                    sn_esperado_emisor = SequenceNumber.next_seq(seq_servidor)

                    logging.info(f"[CLIENTE DOWNLOAD] SYN-ACK recibido de {addr}. SEQ servidor={seq_servidor}, esperando SEQ={sn_esperado_emisor}")

                    # Retornar paquete con flag ACK DOWNLOAD
                    sn_number_receptor = SequenceNumber.next_seq(secuencia_syn)
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

                    # Esperar el siguiente paquete: si es SYN-ACK se duplica tiempo y se reenvía ACK, si son datos se retorna
                    tiempo_datos = timeout
                    intentos_datos = 0
                    while intentos_datos < max_intentos:
                        sock.settimeout(tiempo_datos)
                        try:
                            datos_sig,_ = sock.recvfrom(MTU)
                            paquete_sig = Packet.deserialize(datos_sig)
                            flags_sig = paquete_sig.header.flags

                            if flags_sig.error != ERR_NONE:
                                desc = ERRORES_DESC.get(flags_sig.error, f"Error {flags_sig.error}")
                                raise RuntimeError(f"Error del servidor ({flags_sig.error}): {desc}")

                            # Si vuelve a llegar SYN-ACK, se reenvía el ACK y se duplica el tiempo
                            if flags_sig.syn and flags_sig.ack:
                                sock.sendto(paquete_ack.serialize(), addr)
                                tiempo_datos *= 2
                                intentos_datos += 1
                                continue

                            # Si es un paquete de datos, lo retornamos para iniciar recepción
                            return paquete_sig,SequenceNumber.next_seq(sn_number_receptor) ,sn_esperado_emisor

                        except socket.timeout:
                            # Reenviar ACK si no llega el primer bloque
                            sock.sendto(paquete_ack.serialize(), addr)
                            tiempo_datos *= 2
                            intentos_datos += 1

                    raise TimeoutError("[CLIENTE DOWNLOAD] Tiempo agotado esperando el primer paquete de datos.")

        except socket.timeout:
            logging.debug(f"[CLIENTE DOWNLOAD] Timeout en SYN. Duplicando tiempo de espera.")
            timeout_cont += 1
            timeout *= 2
            continue

    raise TimeoutError("[CLIENTE DOWNLOAD] Error de conexión: demasiados timeouts al iniciar handshake de descarga.")


def recepcion_datos_sack(
    numero_secuencia_esperado: int,
    siguiente_sn_receptor: int,
    primer_paquete: Packet,
    sock: socket.socket,
    direccion_ip: str,
    puerto: int,
    ruta_destino: str = "archivo_recibido.bin",
    timeout_inactividad: float = 10.0
) -> tuple[Packet, int, int]:
    """
    Bucle principal de escucha y procesamiento continuo de datos para la descarga SACK.
    Retorna (paquete_fin_recibido, siguiente_sn_receptor, numero_secuencia_esperado) al detectar el FIN del servidor.
    """
    received_buffer = {}
    address = (direccion_ip, puerto)

    logging.info(f"[CLIENTE DOWNLOAD] Receptor listo, guardando en '{ruta_destino}'...")
    archivo_abierto = open(ruta_destino, "wb")

    try:
        # Procesar el primer paquete si ya fue capturado en el handshake
        if primer_paquete is not None:
            numero_secuencia_esperado, siguiente_sn_receptor, es_fin, pkt_fin = procesar_paquete_recibido(
                primer_paquete,
                received_buffer,
                archivo_abierto,
                numero_secuencia_esperado,
                siguiente_sn_receptor,
                sock,
                address
            )
            if es_fin:
                return pkt_fin, siguiente_sn_receptor, numero_secuencia_esperado

        # Bucle de escucha continuo
        sock.settimeout(timeout_inactividad)
        while True:
            try:
                packet_bytes, addr = sock.recvfrom(MTU)
                numero_secuencia_esperado, siguiente_sn_receptor, es_fin, pkt_fin = procesar_paquete_recibido(
                    packet_bytes,
                    received_buffer,
                    archivo_abierto,
                    numero_secuencia_esperado,
                    siguiente_sn_receptor,
                    sock,
                    addr
                )
                if es_fin:
                    return pkt_fin, siguiente_sn_receptor, numero_secuencia_esperado

            except socket.timeout:
                raise TimeoutError("[CLIENTE DOWNLOAD] Tiempo de espera agotado: no se recibieron más paquetes del servidor.")

    finally:
        archivo_abierto.close()


def finalizar_handshake_fin(
    sock: socket.socket,
    direccion_ip: str,
    puerto: int,
    paquete_fin_servidor: Packet,
    seq_cliente: int,
    timeout_inicial: float = 1.0,
    max_intentos: int = 5
):
    """
    Ejecuta el Four-Way Handshake con Stop and Wait para el cierre ordenado de la conexión:
      - Paso 1: El servidor envió FIN (paquete_fin_servidor).
      - Paso 2: El cliente confirmó con ACK (usando seq_cliente).
      - Paso 3: El cliente envía su propio FIN con Stop and Wait (avanzando seq_cliente a seq_fin_cliente).
      - Paso 4: El cliente espera el ACK del servidor confirmando su FIN.
    """
    servidor_addr = (direccion_ip, puerto)
    timeout = timeout_inicial
    timeout_cont = 0

    # Paquete ACK que confirma el FIN del servidor (Paso 2)
    paquete_ack_fin_servidor = Packet(
        sequence_number=seq_cliente,
        ack_number=paquete_fin_servidor.header.sequence_number,
        flags=HeaderFlags(
            type=HeaderFlags.Type.SACK,
            operation=HeaderFlags.Operation.DOWNLOAD,
            ack=True,
            syn=False,
            fin=False,
            error=ERR_NONE
        )
    )

    # Paso 2: Enviamos la confirmación del FIN que mandó el servidor
    sock.sendto(paquete_ack_fin_servidor.serialize(), servidor_addr)
    logging.info(f"[CLIENTE DOWNLOAD] ACK del FIN del servidor enviado (Paso 2) con SEQ={seq_cliente}.")

    # Avanzar número de secuencia para el FIN del cliente (Paso 3)
    seq_fin_cliente = SequenceNumber.next_seq(seq_cliente)

    # Paquete FIN propio del cliente (Paso 3)
    paquete_fin_cliente = Packet(
        sequence_number=seq_fin_cliente,
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

    # Stop and Wait: Envío del FIN del cliente y espera del ACK del servidor (Pasos 3 y 4)
    while timeout_cont < max_intentos:
        sock.settimeout(timeout)
        try:
            logging.debug(f"[CLIENTE DOWNLOAD] Enviando FIN del cliente con SEQ={seq_fin_cliente} a {servidor_addr} (intento {timeout_cont + 1}/{max_intentos})")
            sock.sendto(paquete_fin_cliente.serialize(), servidor_addr)

            while True:
                datos, addr = sock.recvfrom(MTU)
                respuesta = Packet.deserialize(datos)
                flags = respuesta.header.flags

                # Si el servidor retransmitió su FIN (porque se perdió el ACK del Paso 2), le reenviamos el ACK
                if flags.fin and not flags.ack:
                    sock.sendto(paquete_ack_fin_servidor.serialize(), addr)
                    continue

                # Paso 4: Llegó el ACK del servidor confirmando el FIN del cliente
                if flags.ack and respuesta.header.ack_number == paquete_fin_cliente.header.sequence_number:
                    logging.info("[CLIENTE DOWNLOAD] ACK del FIN recibido del servidor. Conexión cerrada exitosamente (Four-Way Handshake completo).")
                    return

        except socket.timeout:
            logging.debug("[CLIENTE DOWNLOAD] Timeout esperando ACK del FIN. Duplicando tiempo de espera.")
            timeout_cont += 1
            timeout *= 2
            continue

    logging.warning("[CLIENTE DOWNLOAD] Se agotaron los reintentos esperando el ACK del FIN del servidor. Conexión cerrada por timeout.")


def download_sack(nombre_archivo: str, direccion_ip: str, puerto: int, ruta_destino: str | None = None):
    """
    Coordina la descarga completa de un archivo mediante el protocolo SACK:
      1. Abre el socket UDP.
      2. Inicia el handshake de sincronización con el servidor (Stop and Wait).
      3. Ejecuta la recepción y reordenamiento de datos con SACK.
      4. Finaliza la sesión mediante el Four-Way Handshake de FIN (Stop and Wait) y cierra el socket.
    """
    if ruta_destino is None:
        ruta_destino = nombre_archivo

    # 1. Abrir socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 2. Iniciar handshake de sincronización (Stop and Wait)
        primer_paquete_datos, siguiente_sn_receptor, siguiente_sn_esperado_emisor = iniciar_handshake(
            sock, direccion_ip, puerto, nombre_archivo
        )

        # 3. Recepción de datos SACK
        paquete_de_fin, siguiente_sn_receptor, siguiente_sn_esperado_emisor = recepcion_datos_sack(
            numero_secuencia_esperado=siguiente_sn_esperado_emisor,
            siguiente_sn_receptor=siguiente_sn_receptor,
            primer_paquete=primer_paquete_datos,
            sock=sock,
            direccion_ip=direccion_ip,
            puerto=puerto,
            ruta_destino=ruta_destino
        )

        # 4. Handshake de FIN (Four-Way Handshake Stop and Wait)
        finalizar_handshake_fin(
            sock=sock,
            direccion_ip=direccion_ip,
            puerto=puerto,
            paquete_fin_servidor=paquete_de_fin,
            seq_cliente=siguiente_sn_receptor
        )

        logging.info(f"[CLIENTE DOWNLOAD] Descarga de '{nombre_archivo}' completada con éxito en '{ruta_destino}'.")

    finally:
        # Cerrar socket
        sock.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Cliente para descarga de archivos mediante SACK")
    parser.add_argument("archivo", help="Nombre del archivo a descargar del servidor")
    parser.add_argument("-H", "--host", default="127.0.0.1", help="Dirección IP del servidor (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=12345, help="Puerto UDP del servidor (default: 12345)")
    parser.add_argument("-d", "--dst", default=None, help="Ruta de destino donde guardar el archivo descargado")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostrar logs detallados")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s"
    )
    download_sack(args.archivo, args.host, args.port, args.dst)


