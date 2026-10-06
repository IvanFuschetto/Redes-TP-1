import logging
import os.path
import threading

from protocolo import Packet, HeaderFlags, MessageSynUpload, MessageSynDownload, MessageSynAckDownload, \
    ERRORES_DESC, SequenceNumber
from lib.channels import Channel
from lib.sack import SackSender, SackReceiver, RemoteError, sack_flags, read_chunks, send_and_wait, is_response_to, \
    receive_file, time_wait
from lib.validators import validar_upload, validar_download

INACTIVITY_TIMEOUT = 10


def upload_client_handler(channel: Channel, storage_path, stop_event: threading.Event):
    operation = HeaderFlags.Operation.UPLOAD
    channel.settimeout(INACTIVITY_TIMEOUT)

    # Primer paquete en el Channel es el paquete de SYN
    try:
        syn_packet = channel.recv()
    except channel.TimeoutError:
        return

    message = MessageSynUpload.deserialize(syn_packet.payload)
    file_path = os.path.join(storage_path, message.file_name)
    error = validar_upload(message.file_size, file_path)

    syn_ack_packet = Packet(
        0,
        syn_packet.header.sequence_number,
        sack_flags(operation, ack=True, syn=True, error=error),
    )
    channel.send(syn_ack_packet)
    if error:
        logging.warning(f"Error al intentar recibir: {file_path}. ({error}) {ERRORES_DESC[error]}")
        return

    first_seq = SequenceNumber.next_seq(syn_packet.header.sequence_number)
    receiver = SackReceiver(channel, operation, file_path, message.file_size, first_seq)
    fin_ack_packet = None
    try:
        # Si se repite el SYN (se perdió el SYN-ACK), se reenvía la misma respuesta
        fin_ack_packet = receive_file(channel, receiver, on_syn=lambda: channel.send(syn_ack_packet), stop_event=stop_event)
    except OSError as e:
        logging.warning(f"Recepción de {channel.address} fallida: {e}")
    finally:
        receiver.close(keep_file=fin_ack_packet is not None)

    if fin_ack_packet is None:
        return
    logging.info(f"Transferencia de {channel.address} finalizada exitosamente")

    # TIME_WAIT: se reenvía el FIN-ACK si el cliente repite el FIN
    time_wait(channel, fin_ack_packet, should_resend=lambda p: p.header.flags.fin, duration=INACTIVITY_TIMEOUT, stop_event=stop_event)


def download_client_handler(channel: Channel, storage_path, stop_event: threading.Event):
    operation = HeaderFlags.Operation.DOWNLOAD
    channel.settimeout(INACTIVITY_TIMEOUT)

    # Primer paquete en el Channel es el paquete de SYN
    try:
        syn_packet = channel.recv()
    except channel.TimeoutError:
        return

    message = MessageSynDownload.deserialize(syn_packet.payload)
    file_path = os.path.join(storage_path, message.file_name)
    error = validar_download(file_path)

    syn_ack_packet = Packet(
        0,
        syn_packet.header.sequence_number,
        sack_flags(operation, ack=True, syn=True, error=error),
        MessageSynAckDownload(0 if error else os.path.getsize(file_path)).serialize(),
    )
    if error:
        channel.send(syn_ack_packet)
        logging.warning(f"Error al intentar enviar: {file_path}. ({error}) {ERRORES_DESC[error]}")
        return

    try:
        # Handshake: se espera el ACK del cliente al SYN-ACK antes de empezar a enviar datos
        timeout, _ = send_and_wait(channel, syn_ack_packet, accept=is_response_to(syn_ack_packet))

        sender = SackSender(channel, operation, base=SequenceNumber.next_seq(syn_ack_packet.header.sequence_number), timeout=timeout)
        sender.send_chunks(read_chunks(file_path), stop_event)

        fin_packet = Packet(sender.next_seq, 0, sack_flags(operation, fin=True))
        send_and_wait(channel, fin_packet, accept=is_response_to(fin_packet, fin=True))
        logging.info(f"Transferencia a {channel.address} finalizada exitosamente")

    except RemoteError as e:
        logging.warning(f"Transferencia a {channel.address} abortada por el cliente: {e}")
    except OSError as e:
        logging.warning(f"Transferencia a {channel.address} fallida: {e}")
