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



