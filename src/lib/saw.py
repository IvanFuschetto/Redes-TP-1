import logging
import threading
import time

from lib.protocolo import MAX_PAYLOAD, ERRORES_DESC, \
    Packet, HeaderFlags, ERR_IO_INTERNO
from .channels import Channel, get_next_sequence_number


def try_send(channel: Channel, packet: Packet) -> Packet:
    """
    Intenta y reintenta enviar el `packet` a través de `sock` a `address`.
    Devuelve el Packet recibido.
    """
    timeout_cont = 10  # 5
    while timeout_cont > 0:
        try:
            ack_number_esperado = packet.header.sequence_number
            channel.send(packet)

            time_start = time.monotonic()

            logging.debug(f"Enviando {packet} | TO={channel._timeout:.3f}")

            while True:
                respuesta = channel.recv()
                logging.debug(f"Recibido {respuesta}")

                if (
                    respuesta.header.flags.ack
                    and
                    respuesta.header.ack_number == ack_number_esperado
                ):

                    time_end = time.monotonic()
                    channel.settimeout_by_rtt(time_end - time_start)

                    return respuesta

        except channel.TimeoutError:
            logging.debug(f"Timeout {packet}")
            timeout_cont -= 1
            channel.settimeout_by_expired()
            continue

    raise TimeoutError("Error de Conexión ! Demasiados Timeouts")


def send_file(channel: Channel, source_path, operation: HeaderFlags.Operation):
    """
    Envía el contenido de `source_path` a través de `channel`.
    Espera recibir confirmación (ACK) por cada paquete enviado
    a través de `channel`.Devuelve una tupla con:
    - flag de transferencia finalizada: bool
    """
    finished = False
    with open(source_path, "rb") as f:
        while True:

            chunk = f.read(MAX_PAYLOAD)
            if not chunk:
                finished = True
                break

            packet = Packet(
                sequence_number=channel.get_next_sequence_number_to_send(),
                ack_number=0,
                flags=HeaderFlags(
                    type=HeaderFlags.Type.SAW,
                    operation=operation,
                    ack=False, syn=False, fin=False,
                ),
                payload=chunk
            )
            respuesta = try_send(channel, packet)
            if respuesta.header.flags.error:
                logging.error(f"({respuesta.header.flags.error}) "
                              f"{ERRORES_DESC[respuesta.header.flags.error]}")
                break

    if finished:
        # FIN: START
        packet = Packet(
            sequence_number=channel.get_next_sequence_number_to_send(),
            ack_number=0,
            flags=HeaderFlags(
                type=HeaderFlags.Type.SAW,
                operation=operation,
                ack=False, syn=False, fin=True,
            )
        )
        respuesta = try_send(channel, packet)
        if respuesta.header.flags.error:
            logging.error(f"({respuesta.header.flags.error}) "
                          f"{ERRORES_DESC[respuesta.header.flags.error]}")

    return finished


def receive_file(channel: Channel, dest_path, stop_event: threading.Event):
    """
    Recibe el contenido a través de `channel` y lo escribe en `dest_path`.
    Envía una confirmación (ACK) por cada paquete recibido.
    La recepción finaliza cuando se recibe un FIN.
    """
    expected_sequence_number = channel.get_next_sequence_number_to_receive()
    timeout_count = 5
    logging.debug(f"Channel Timeout: {channel._timeout}")
    with open(dest_path, "wb") as file:
        while timeout_count > 0 and not stop_event.is_set():
            try:
                packet_received = channel.recv()
                timeout_count = 5

                logging.debug(f"{channel.address}: "
                              f"Recibido {packet_received}")

                # CONTROL DE SECUENCIALIDAD:
                if (
                    expected_sequence_number !=
                    packet_received.header.sequence_number
                    or packet_received.header.flags.syn
                ):
                    logging.debug(
                        f"{channel.address}: *** ERR CTRL SEQ: "
                        f"EXPSN:{expected_sequence_number} "
                        f"RECSN:{packet_received.header.sequence_number} "
                        f"SYN:{packet_received.header.flags.syn}")
                    # Se reenvía el último paquete enviado
                    channel.resend()
                    continue

                error_code = 0

                if not packet_received.header.flags.fin:
                    datos = packet_received.payload
                    try:
                        file.write(datos)
                    except IOError as e:
                        logging.error(f"{channel.address}: "
                                      "Error al escribir en el archivo "
                                      f"{file.name}: {e}")
                        error_code = ERR_IO_INTERNO  # Error IO Interno

                packet = Packet(
                    sequence_number=0,
                    ack_number=packet_received.header.sequence_number,
                    flags=HeaderFlags(
                        packet_received.header.flags.type,
                        packet_received.header.flags.operation,
                        ack=True,
                        syn=False,
                        fin=packet_received.header.flags.fin,
                        error=error_code
                    ),
                )

                channel.send(packet)
                expected_sequence_number = get_next_sequence_number(
                    expected_sequence_number
                )

                if packet_received.header.flags.fin:
                    return

            except channel.TimeoutError:
                logging.debug("Timeout Error !")
                channel.settimeout_by_expired()
                timeout_count -= 1
                continue

    if timeout_count == 0:
        raise TimeoutError("Error de Conexión ! Demasiados Timeouts")
