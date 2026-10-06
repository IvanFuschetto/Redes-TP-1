import logging
import os

from lib.protocolo import ERRORES_DESC, Packet, HeaderFlags, \
    SequenceNumber, MessageSynUpload, MessageSynDownload, \
    MessageSynAckDownload

from .channels import Channel
from .sack import SackSender, SackReceiver, \
    sack_flags, read_chunks, send_and_wait, is_response_to, receive_file, \
    time_wait

# Tiempo sin recibir nada del servidor para dar la descarga por fallida
INACTIVITY_TIMEOUT = 10
# Tiempo que se sigue escuchando
# tras el FIN-ACK por si el servidor repite el FIN
TIME_WAIT = 3


def upload(channel: Channel, source_path, dest_filename):
    """
    Realiza la transferencia de `source_path` a través de `channel`
    desde el Cliente hacia el Servidor usando SACK.
    El nombre del archivo en el servidor será `dest_filename`.
    """
    operation = HeaderFlags.Operation.UPLOAD

    # SYN: START
    packet = Packet(
        sequence_number=0,
        ack_number=0,
        flags=sack_flags(operation, syn=True),
        payload=MessageSynUpload(
            file_size=os.path.getsize(source_path),
            file_name=dest_filename,
        ).serialize()
    )
    timeout, respuesta = send_and_wait(channel,
                                       packet,
                                       accept=is_response_to(packet,
                                                             syn=True))
    if respuesta.header.flags.error:
        logging.error(f"({respuesta.header.flags.error}) "
                      f"{ERRORES_DESC[respuesta.header.flags.error]}")
        return
    # SYN: FINISH

    chunks = read_chunks(source_path)

    # Envío de chunks con SACK.
    # Si el servidor informa un error en un ACK, se lanza RemoteError
    sender = SackSender(channel,
                        operation,
                        base=SequenceNumber.next_seq(
                                packet.header.sequence_number
                        ),
                        timeout=timeout
                        )
    logging.info("[CLIENTE] Enviando archivo con SACK...")
    sender.send_chunks(chunks)

    # FIN
    packet = Packet(
        sequence_number=sender.next_seq,
        ack_number=0,
        flags=sack_flags(operation, fin=True),
    )
    _, respuesta = send_and_wait(channel,
                                 packet,
                                 accept=is_response_to(packet, fin=True))
    if respuesta.header.flags.error:
        logging.error(f"({respuesta.header.flags.error}) "
                      f"{ERRORES_DESC[respuesta.header.flags.error]}")
        return

    logging.info(f"[CLIENTE] Archivo '{dest_filename}' "
                 f"subido con éxito ({len(chunks)} paquetes).")


def download(channel: Channel, filename_server, dest_filename):
    """
    Realiza la transferencia de `filename_server` a través de `channel`
    en el cliente desde el Servidor usando SACK.
    El servidor es el emisor (SackSender)
    y el cliente el receptor (SackReceiver).
    El nombre del archivo en el cliente será `dest_filename`.
    """
    operation = HeaderFlags.Operation.DOWNLOAD

    # SYN: START
    packet = Packet(
        sequence_number=0,
        ack_number=0,
        flags=sack_flags(operation, syn=True),
        payload=MessageSynDownload(file_name=filename_server).serialize()
    )
    _, respuesta = send_and_wait(channel,
                                 packet,
                                 accept=is_response_to(packet, syn=True))
    if respuesta.header.flags.error:
        logging.error(f"({respuesta.header.flags.error}) "
                      f"{ERRORES_DESC[respuesta.header.flags.error]}")
        return

    file_size = MessageSynAckDownload.deserialize(respuesta.payload).file_size
    first_seq = SequenceNumber.next_seq(respuesta.header.sequence_number)
    receiver = SackReceiver(channel,
                            operation,
                            dest_filename,
                            file_size, first_seq)

    # READY ACK
    # Es el ACK acumulativo inicial del
    # receptor (ack_number = SN del SYN-ACK).
    # Si se pierde, el servidor repite el SYN-ACK
    # y receive_file vuelve a enviarlo.
    receiver.send_ack()
    # SYN: FINISH

    channel.settimeout(INACTIVITY_TIMEOUT)
    fin_ack_packet = None
    try:
        fin_ack_packet = receive_file(channel,
                                      receiver,
                                      on_syn=receiver.send_ack)
    finally:
        receiver.close(keep_file=fin_ack_packet is not None)

    logging.info(f"[CLIENTE] Archivo '{filename_server}' descargado "
                 f"con éxito en '{dest_filename}' "
                 f"({receiver.bytes_written} bytes).")

    # TIME_WAIT: se reenvía el FIN-ACK si el servidor repite el FIN
    time_wait(channel,
              fin_ack_packet,
              should_resend=lambda p: p.header.flags.fin, duration=TIME_WAIT)
