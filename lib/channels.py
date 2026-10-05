from abc import ABC, abstractmethod
import socket
from queue import Queue, Empty

from protocolo import Packet, HEADER_SIZE, MAX_PAYLOAD


def get_next_sequence_number(sequence_number) -> int:
    if sequence_number is None:
        return 1
    return (sequence_number + 1) % 256


class Channel(ABC):
    """
    Abstracción de un canal de comunicación a través del cual
    se puede enviar y recibir paquetes, y configurar un timeout.
    """
    def __init__(self, address):
        self.__last_sequence_number_received = None
        self.__last_sequence_number_sent = None
        self.__last_packet_sent = None
        self.__address = address
        self._timeout = 1
        self.rtt_estimated = 1.0
        self.rtt_deviation = 1.0
        self.settimeout(self._timeout)

    @abstractmethod
    def send(self, packet: Packet) -> Packet:
        pass

    @abstractmethod
    def recv(self) -> Packet:
        pass

    def settimeout(self, timeout: float) -> None:
        self._timeout = timeout
        self._settimeout(timeout)

    @abstractmethod
    def _settimeout(self, timeout: float) -> None:
        pass

    def settimeout_by_rtt(self, rtt: float) -> None:
        self.rtt_estimated = 0.875 * self.rtt_estimated + 0.125 * abs(rtt)
        self.rtt_deviation = 0.75 * self.rtt_deviation + 0.25 * abs(rtt - self.rtt_estimated)
        self._timeout = self.rtt_estimated + 4 * self.rtt_deviation
        self.settimeout(self._timeout)

    def settimeout_by_expired(self) -> None:
        self._timeout = min(10, self._timeout * 2)
        self.settimeout(self._timeout)

    @property
    def TimeoutError(self):
        pass

    @property
    def last_sequence_number_received(self) -> int:
        return self.__last_sequence_number_received

    @property
    def last_sequence_number_sent(self) -> int:
        return self.__last_sequence_number_sent

    @property
    def address(self):
        return self.__address

    def _update_last_sequence_number_received(self, sequence_number) -> None:
        self.__last_sequence_number_received = sequence_number

    def _update_last_sequence_number_sent(self, sequence_number) -> None:
        self.__last_sequence_number_sent = sequence_number

    def _update_last_packet_sent(self, packet: Packet) -> None:
        self.__last_packet_sent = packet

    def get_next_sequence_number_to_receive(self) -> int:
        return get_next_sequence_number(self.last_sequence_number_received)

    def get_next_sequence_number_to_send(self) -> int:
        return get_next_sequence_number(self.last_sequence_number_sent)

    def resend(self) -> None:
        if self.__last_packet_sent is not None:
            self.send(self.__last_packet_sent)


class ServerChannel(Channel):
    """
    Abstracción de un canal de comunicación hacia el servidor.
    Permite enviar y recibir paquetes a través de un socket UDP.
    """
    def __init__(self, sock: socket.socket, server_address):
        self.sock = sock
        self.server_address = server_address
        super().__init__(server_address)

    def send(self, packet: Packet) -> None:
        self.sock.sendto(packet.serialize(), self.server_address)
        self._update_last_sequence_number_sent(packet.header.sequence_number)
        self._update_last_packet_sent(packet)

    def recv(self) -> Packet:
        respuesta_bytes, _ = self.sock.recvfrom(HEADER_SIZE + MAX_PAYLOAD)
        packet = Packet.deserialize(respuesta_bytes)
        self._update_last_sequence_number_received(packet.header.sequence_number)
        return packet

    def _settimeout(self, timeout: float) -> None:
        self.sock.settimeout(timeout)

    @property
    def TimeoutError(self):
        return socket.timeout


class ClientChannel(Channel):
    """
    Abstracción de un canal de comunicación con un cliente.
    Permite enviar paquetes a través de un socket UDP y
    recibir paquetes a través de una Cola, y configurar un timeout.
    """
    def __init__(self, sender_socket: socket.socket, receiver_queue: Queue, client_address):
        self.sender_socket = sender_socket
        self.receiver_queue = receiver_queue
        self.client_address = client_address
        super().__init__(client_address)

    def send(self, packet: Packet) -> None:
        self.sender_socket.sendto(packet.serialize(), self.client_address)
        self._update_last_sequence_number_sent(packet.header.sequence_number)
        self._update_last_packet_sent(packet)

    def recv(self) -> Packet:
        packet = self.receiver_queue.get(block=True, timeout=self._timeout)
        self._update_last_sequence_number_received(packet.header.sequence_number)
        return packet

    def _settimeout(self, timeout: float) -> None:
        pass

    @property
    def TimeoutError(self):
        return Empty
