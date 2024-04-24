from math import ceil

from bitarray import bitarray
from Crypto.Hash import SHA512

NB_ROUNDS = 14


def hash_half(half: bitarray, symmetric_key: bytes, index: int) -> bitarray:
    """
    Returns a hash of `half` of size equal to the size of `half` using SHA512.

    `symmetric_size` and `index` are also hashed alongside `half`.
    """
    result = bitarray()
    hash_prefix = half.tobytes() + symmetric_key + str(index).encode()

    for i in range(ceil(len(half) / 512)):
        new_bits = bitarray()
        new_bits.frombytes(SHA512.new(hash_prefix + str(i).encode()).digest())
        result += new_bits

    return result[: len(half)]


def encrypt(symmetric_key: bytes, message: bitarray) -> bitarray:
    """
    Symmetric encryption of message using two-round Feistel,
    as described in https://eprint.iacr.org/2015/876.pdf
    """

    if len(message) % 2 != 0 or len(message) == 0:
        raise ValueError("Message must be of even length, and not empty.")

    left = message[: len(message) // 2]  # Left half
    right = message[len(message) // 2 :]  # Right half

    new_left: bitarray = bitarray()
    new_right: bitarray = bitarray()

    for i in range(NB_ROUNDS // 2):
        new_left = left ^ hash_half(right, symmetric_key, 2 * i)
        new_right = right ^ hash_half(new_left, symmetric_key, 2 * i + 1)

        right = new_right
        left = new_left

    return new_left + new_right


def decrypt(symmetric__key: bytes, cipher: bitarray) -> bitarray:
    """
    Symmetric decryption of message using two-round Feistel,
    as described in https://eprint.iacr.org/2015/876.pdf
    """

    if len(cipher) % 2 != 0 or len(cipher) == 0:
        raise ValueError("Message must be of even length, and not empty.")

    left = cipher[: len(cipher) // 2]  # Left half
    right = cipher[len(cipher) // 2 :]  # Right half

    new_left: bitarray = bitarray()
    new_right: bitarray = bitarray()

    for i in range(NB_ROUNDS // 2 - 1, -1, -1):
        new_right = right ^ hash_half(left, symmetric__key, 2 * i + 1)
        new_left = left ^ hash_half(new_right, symmetric__key, 2 * i)

        right = new_right
        left = new_left

    return new_left + new_right
