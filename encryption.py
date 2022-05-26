from Crypto.Cipher import AES   # 加密演算法-引用AES加密
from Crypto import Random   # produce random encryption key
import struct   # Interpret bytes as packed binary data
import json

max_buffer_size = 2048
key = b'86Y4xTrT2mVMNgdK'   # AES-128 (16 bits)


def encrypt(data):
    code = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, code)
    return code + cipher.encrypt(data)


def decrypt(data):
    code = data[:16]   # get encrypt key
    ciphered_data = data[16:]  # get encrypted data
    cipher = AES.new(key, AES.MODE_CFB, code)
    return cipher.decrypt(ciphered_data)


def pack(data):
    # H: unsigned short (2 bytes)
    # pack(format, v1, v2, ....)
    return struct.pack('>H', len(data)) + data


def send(socket, data_dict):
    # json.dumps = change python object into json string
    socket.send(pack(encrypt(json.dumps(data_dict).encode('utf-8'))))


def recv(socket):
    data = b''
    data_size = struct.unpack('>H', socket.recv(2))[0]
    socket.settimeout(5)

    while data_size:
        recv_data = socket.recv(max_buffer_size if data_size > max_buffer_size else data_size)
        data += recv_data
        data_size -= len(recv_data)
    socket.settimeout(None)

    # json.loads = change json string into python object
    return json.loads(decrypt(data))
