"""
Header = 3 bytes
    byte 0 -> Sequence Number (0-255)
    byte 1 -> Ack Number      (0-255)
    byte 2 -> Flags
        bit 7: SACK / SW   -> 1 = SACK, 0 = Stop and Wait
        bit 6: UPLOAD/DOWNLOAD -> 1 = upload, 0 = download
        bit 5: ACK
        bit 4: SYN
        bit 3: FIN
        bits 2-0: codigo de error (3 bits -> 0 a 7)
"""
from email.header import Header
from enum import Enum

HEADER_SIZE = 3
MAX_PAYLOAD = 1447
MTU = HEADER_SIZE + MAX_PAYLOAD + 20 + 8  # 20 bytes IP header + 8 bytes UDP header

# posiciones de cada bit dentro del byte de flags
BIT_SACK = 7
BIT_UPDOWN = 6
BIT_ACK = 5
BIT_SYN = 4
BIT_FIN = 3
ERROR_MASK = 0b00000111  # bits 2,1,0
 
# codigos de error (van en los 3 bits bajos del byte de flags)
ERR_NONE = 0
ERR_INVALID_NAME = 1
ERR_FILE_EXISTS = 2
ERR_FILE_TOO_BIG = 3
 
ERRORES_DESC = {
    ERR_NONE: "sin error",
    ERR_INVALID_NAME: "nombre de archivo invalido",
    ERR_FILE_EXISTS: "el archivo ya existe en el servidor",
    ERR_FILE_TOO_BIG: "el archivo es demasiado grande",
}
 
 
def build_flags(sack=0, updown=0, ack=0, syn=0, fin=0, error=ERR_NONE):
    """Arma el byte de flags a partir de cada campo individual."""
    flags = 0
    flags |= (sack & 1) << BIT_SACK
    flags |= (updown & 1) << BIT_UPDOWN
    flags |= (ack & 1) << BIT_ACK
    flags |= (syn & 1) << BIT_SYN
    flags |= (fin & 1) << BIT_FIN
    flags |= (error & ERROR_MASK)
    return flags & 0xFF

def parse_flags(flags_byte):
    """Devuelve un dict con cada campo del byte de flags ya separado."""
    return {
        "sack": (flags_byte >> BIT_SACK) & 1,
        "updown": (flags_byte >> BIT_UPDOWN) & 1,
        "ack": (flags_byte >> BIT_ACK) & 1,
        "syn": (flags_byte >> BIT_SYN) & 1,
        "fin": (flags_byte >> BIT_FIN) & 1,
        "error": flags_byte & ERROR_MASK,
    }
 
 
def make_packet(seq, ack_num, flags_byte, payload=b""):
    """Arma el paquete completo: header (3 bytes) + payload."""
    header = bytes([seq & 0xFF, ack_num & 0xFF, flags_byte & 0xFF])
    return header + payload
 
 
def parse_packet(data):
    """Separa un paquete recibido en (seq, ack_num, flags_byte, payload)."""
    seq = data[0]
    ack_num = data[1]
    flags_byte = data[2]
    payload = data[HEADER_SIZE:]
    return seq, ack_num, flags_byte, payload




class HeaderFlags:
    class Type(Enum):
        SAW = 0
        SACK = 1

    class Operation(Enum):
        DOWNLOAD = 0
        UPLOAD = 1

    def __init__(self, type: Type, operation: Operation, ack: bool, syn: bool, fin: bool, error: int = 0):
        if not isinstance(error, int) or not 0 <= error <= 7:
            raise ValueError(f"El valor de error no es valido: {error}")
        self.type = type
        self.operation = operation
        self.ack = ack
        self.syn = syn
        self.fin = fin
        self.error = error

    def serialize(self):
        flags = 0
        flags |= (self.type.value & 1) << BIT_SACK
        flags |= (self.operation.value & 1) << BIT_UPDOWN
        flags |= (self.ack & 1) << BIT_ACK
        flags |= (self.syn & 1) << BIT_SYN
        flags |= (self.fin & 1) << BIT_FIN
        flags |= (self.error & ERROR_MASK)
        return (flags & 0xFF).to_bytes(length=1, byteorder='big')

    @classmethod
    def deserialize(cls, flags_byte: bytes):
        tipo = cls.Type((flags_byte >> BIT_SACK) & 1)
        operation = cls.Operation((flags_byte >> BIT_UPDOWN) & 1)
        ack = bool((flags_byte >> BIT_ACK) & 1)
        syn = bool((flags_byte >> BIT_SYN) & 1)
        fin = bool((flags_byte >> BIT_FIN) & 1)
        error = flags_byte & ERROR_MASK
        return cls(tipo, operation, ack, syn, fin, error)

    def __eq__(self, other):
        if not isinstance(other, HeaderFlags):
            return False
        return self.type == other.type and self.operation == other.operation and self.ack == other.ack and self.syn == other.syn and self.fin == other.fin and self.error == other.error

    def __str__(self):
        return f"(TY={self.type.name},OP={self.operation.name[0]},ACK={int(self.ack)},SYN={int(self.syn)},FIN={int(self.fin)},ERR={self.error})"


def test_HeaderFlags_serialize():
    assert HeaderFlags(HeaderFlags.Type.SAW, HeaderFlags.Operation.UPLOAD, True, False, True).serialize() == 0b01101000.to_bytes(length=1, byteorder='big')
    assert HeaderFlags(HeaderFlags.Type.SAW, HeaderFlags.Operation.DOWNLOAD, True, False, True, 1).serialize() == 0b00101001.to_bytes(length=1, byteorder='big')
    assert HeaderFlags(HeaderFlags.Type.SACK, HeaderFlags.Operation.UPLOAD, True, False, True, 3).serialize() == 0b11101011.to_bytes(length=1, byteorder='big')

def test_HeaderFlags_deserialize():
    assert HeaderFlags.deserialize(0b01101000) == HeaderFlags(HeaderFlags.Type.SAW, HeaderFlags.Operation.UPLOAD, True, False, True)
    assert HeaderFlags.deserialize(0b00101001) == HeaderFlags(HeaderFlags.Type.SAW, HeaderFlags.Operation.DOWNLOAD, True, False, True, 1)
    assert HeaderFlags.deserialize(0b11101011) == HeaderFlags(HeaderFlags.Type.SACK, HeaderFlags.Operation.UPLOAD, True, False, True, 3)


class PacketHeader:
    """
    Abstracción de Encabezado de un Paquete del Protocolo RDT.
    """
    def __init__(self, sequence_number: int, ack_number: int, flags: HeaderFlags):
        self.sequence_number = sequence_number
        self.ack_number = ack_number
        self.flags = flags

    def serialize(self) -> bytes:
        sn = int.to_bytes(self.sequence_number, length=1, byteorder='big')
        an = int.to_bytes(self.ack_number, length=1, byteorder='big')
        f = self.flags.serialize()
        return sn + an + f

    @classmethod
    def deserialize(cls, data: bytes):
        sn = int.from_bytes(data[:1], byteorder='big')
        an = int.from_bytes(data[1:2], byteorder='big')
        f = HeaderFlags.deserialize(data[2])
        return cls(sn, an, f)

def test_HeaderFlags():
    packet = PacketHeader.deserialize(PacketHeader(12, 8, HeaderFlags(HeaderFlags.Type.SAW, HeaderFlags.Operation.UPLOAD, True, False, True)).serialize())
    assert packet.sequence_number == 12
    assert packet.ack_number == 8
    assert packet.flags == HeaderFlags(HeaderFlags.Type.SAW, HeaderFlags.Operation.UPLOAD, True, False, True)

class Packet:
    """
    Abstracción de Paquete del Protocolo RDT.
    """
    def __init__(self, sequence_number, ack_number, flags, payload=None):
        self.header = PacketHeader(sequence_number, ack_number, flags)
        self.payload = payload

    def serialize(self):
        if self.payload is None:
            return self.header.serialize()
        return self.header.serialize() + self.payload
    
    @classmethod
    def deserialize(cls, packet_bytes):
        header = PacketHeader.deserialize(packet_bytes[:HEADER_SIZE])
        payload = packet_bytes[HEADER_SIZE:]
        return cls(header.sequence_number, header.ack_number, header.flags, payload)

    def __str__(self):
        return f"[SN={self.header.sequence_number},ACKN={self.header.ack_number},{self.header.flags}]"




class MessageSynUpload:
    """
    Abstracción de un mensaje de Sincronización para iniciar operacion UPLOAD.
    Se informa tamaño del archivo a subir y el nombre que debe tener en el destino.
    """
    def __init__(self, file_size: int, file_name: str):
        if file_size > 0xFFFFFF:
            raise ValueError(f"Tamaño de archivo muy grande. Máximo: 15 MiB")
        self.file_size = file_size
        self.file_name = file_name

    def serialize(self):
        fsize = int.to_bytes(self.file_size, length=3, byteorder='big')
        fn_len = int.to_bytes(len(self.file_name), length=1, byteorder="big")
        fn = self.file_name.encode()
        return fsize + fn_len + fn

    @classmethod
    def deserialize(cls, message):
        fsize = int.from_bytes(message[:3], byteorder='big')
        fn_len = int.from_bytes(message[3:4], byteorder='big')
        fn = message[4:4+fn_len].decode()
        return cls(fsize, fn)

def test_MessageSynUpload():
    message = MessageSynUpload.deserialize(MessageSynUpload(1024, "Hola.txt").serialize())
    assert message.file_size == 1024
    assert message.file_name == "Hola.txt"