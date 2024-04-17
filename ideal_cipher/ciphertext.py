from bitarray import bitarray

from . import feistel


def encrypt(ciphertext: bytes, symmetric_key: bytes) -> bitarray:
    ciphertext_bits = bitarray()
    ciphertext_bits.frombytes(ciphertext)
    return feistel.encrypt(symmetric_key, ciphertext_bits)


def decrypt(encrypted_ciphertext: bitarray, symmetric_key: bytes) -> bytes:
    return feistel.decrypt(symmetric_key, encrypted_ciphertext).tobytes()
