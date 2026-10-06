import logging
import os.path
import threading

from protocolo import Packet, MessageSynUpload, \
    HeaderFlags, MessageSynDownload
from lib.channels import Channel
from lib.saw import receive_file, send_file
from lib.validators import validar_upload, validar_download


def download_client_handler(channel: Channel,
                            storage_path,
                            stop_event: threading.Event):
    # Timeout de 5 seg en la lectura del channel
    channel.settimeout(5)

    packet_received = channel.recv()

    # Primer paquete en el Channel es el paquete de SYN
    message = MessageSynDownload.deserialize(packet_received.payload)
    file_path = os.path.join(storage_path, message.file_name)
    error = validar_download(file_path)

    packet = Packet(
        channel.get_next_sequence_number_to_send(),
        packet_received.header.sequence_number,
        HeaderFlags(
            packet_received.header.flags.type,
            packet_received.header.flags.operation,
            ack=True, syn=True, fin=False, error=error
        ),
    )

    channel.send(packet)

    # Espero el READY ACK
    # SN+1 & ACK
    timeout_cont = 5
    while timeout_cont > 0:
        try:
            packet_received = channel.recv()
            if not packet_received.header.flags.ack:
                channel.resend()
            else:
                # READY ACK recibido
                break
        except channel.TimeoutError:
            timeout_cont -= 1

    if not error:
        # READY FOR SENDING FILE
        try:
            finished = send_file(channel,
                                 file_path,
                                 HeaderFlags.Operation.DOWNLOAD)
            if finished:
                logging.info(f"Transferencia a {channel.address} "
                             "finalizada exitosamente")
                return
        except TimeoutError as e:
            logging.info(f"Transferencia a {channel.address} "
                         f"finalizada con problemas: {e}")

    else:
        logging.info(f"Transferencia a {channel.address} "
                     "finalizada con problemas")


def upload_client_handler(channel: Channel,
                          storage_path,
                          stop_event: threading.Event):
    # Timeout de 5 seg en la lectura del channel
    channel.settimeout(5)

    packet_received = channel.recv()

    # Primer paquete en el Channel es el paquete de SYN
    message = MessageSynUpload.deserialize(packet_received.payload)
    file_size = message.file_size
    file_path = os.path.join(storage_path, message.file_name)
    error = validar_upload(file_size, file_path)

    packet = Packet(
        0,
        packet_received.header.sequence_number,
        HeaderFlags(
            packet_received.header.flags.type,
            packet_received.header.flags.operation,
            ack=True, syn=True, fin=False, error=error
        ),
    )

    channel.send(packet)

    if not error:
        try:
            receive_file(channel, file_path, stop_event)
            logging.debug(f"Recepción de {channel.address} finalizada.")
        except TimeoutError as e:
            logging.warning(f"Recepción de {channel.address} fallida: {e}")
            # Removemos el archivo recibido parcialmente
            if os.path.exists(file_path):
                os.remove(file_path)
            return

    # Timeout de 10 seg en la lectura del channel:
    # Estado TIME_WAIT para asegurar que el cliente recibió FIN+ACK
    channel.settimeout(10)
    while not stop_event.is_set():
        try:
            channel.recv()
            # Si el cliente envió algo
            # es porque NO RECIBIÓ mi
            # último paquete (FIN+ACK)
            channel.resend()
        except channel.TimeoutError:
            break

    logging.info(f"Transferencia de {channel.address} "
                 "finalizada exitosamente")
