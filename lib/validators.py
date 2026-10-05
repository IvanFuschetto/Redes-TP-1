import os.path

from protocolo import ERR_FILE_TOO_BIG, ERR_FILE_EXISTS, ERR_FILE_NOT_EXISTS

MAX_FILE_SIZE = 15 * 1024 * 1024

def validar_upload(file_size, file_path):
    if file_size is not None and file_size > MAX_FILE_SIZE:
        return ERR_FILE_TOO_BIG
    if os.path.exists(file_path):
        return ERR_FILE_EXISTS
    return 0

def validar_download(file_path):
    if not os.path.exists(file_path):
        return ERR_FILE_NOT_EXISTS
    return 0