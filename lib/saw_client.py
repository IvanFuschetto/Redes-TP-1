import logging
import os
import threading

from protocolo import ERRORES_DESC, Packet, HeaderFlags, \
    MessageSynUpload, MessageSynDownload

from .channels import Channel
from .saw import try_send, send_file, receive_file


def upload(channel: Channel, source_path, dest_filename):
    """
    Realiza la transferencia de `source_path` a través de `channel`
    desde el Cliente hacia el Servidor.
    El nombre del archivo en el servidor será `dest_filename`.
    """

    # SYN: START
    sequence_number = channel.get_next_sequence_number_to_send()
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
    respuesta = try_send(channel, packet)
    if respuesta.header.flags.error:
        logging.error(f"({respuesta.header.flags.error}) "
                      f"{ERRORES_DESC[respuesta.header.flags.error]}")
        return
    # SYN: FINISH
    try:
        if send_file(channel, source_path, HeaderFlags.Operation.UPLOAD):
            logging.info("Transferencia finalizada correctamente.")
        else:
            logging.critical("Transferencia fallida.")
    except TimeoutError as e:
        logging.critical(f"Transferencia fallida: {e}")


def download(channel: Channel, filename_server, dest_filename):
    """
    Realiza la transferencia de `filename_server` a través de `channel`
    en el cliente desde el Servidor.
    El nombre del archivo en el cliente será `dest_filename`.
    """
    # SYN: START
    sequence_number = channel.get_next_sequence_number_to_send()
    packet = Packet(
        sequence_number=sequence_number,
        ack_number=0,
        flags=HeaderFlags(
            type=HeaderFlags.Type.SAW,
            operation=HeaderFlags.Operation.DOWNLOAD,
            ack=False, syn=True, fin=False,
        ),
        payload=MessageSynDownload(
            file_name=filename_server,
        ).serialize()
    )
    respuesta = try_send(channel, packet)

    # READY ACK
    packet = Packet(
        sequence_number=channel.get_next_sequence_number_to_send(),
        ack_number=respuesta.header.sequence_number,
        flags=HeaderFlags(
            type=HeaderFlags.Type.SAW,
            operation=HeaderFlags.Operation.DOWNLOAD,
            ack=True, syn=False, fin=False,
        ),
    )
    channel.send(packet)
    # SYN: FINISH

    if respuesta.header.flags.error:
        logging.error(f"({respuesta.header.flags.error}) "
                      f"{ERRORES_DESC[respuesta.header.flags.error]}")
        return

    stop_event = threading.Event()
    try:
        receive_file(channel, dest_filename, stop_event)
        logging.debug("Recepción finalizada.")
    except TimeoutError as e:
        logging.error(f"Recepción fallida: {e}")
        # Eliminamos el archivo recibido parcialmente
        if os.path.exists(dest_filename):
            os.remove(dest_filename)
        return

    # Timeout de 10 seg en la lectura del channel:
    # Estado TIME_WAIT para asegurar que el cliente recibió FIN+ACK
    channel.settimeout(10)
    while True:
        try:
            channel.recv()
            # Si el cliente envió algo
            # es porque NO RECIBIÓ mi
            # último paquete (FIN+ACK)
            channel.resend()
        except channel.TimeoutError:
            break

    logging.info(f"Transferencia de {channel.address} finalizada exitosamente")
