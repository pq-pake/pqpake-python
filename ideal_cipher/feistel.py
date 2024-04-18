from math import ceil

from bitarray import bitarray
from Crypto.Hash import SHA512

NB_ROUNDS = 14


def hash_half(symmetric_key: bytes, half: bitarray) -> bitarray:
    """
    Returns a hash of `half` of size equal to
    the size of `half` using SHA512.
    The symmetric key is hashed with the half.
    """
    result = bitarray()
    for i in range(ceil(len(half) / 512)):
        new_bits = bitarray()
        new_bits.frombytes(
            SHA512.new(symmetric_key + str(i).encode() + half.tobytes()).digest()
        )
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

    for _ in range(NB_ROUNDS):
        new_left = left ^ hash_half(symmetric_key, right)
        new_right = right ^ hash_half(symmetric_key, new_left)

        right = new_right
        left = new_left

    return new_left + new_right


def decrypt(sym_key: bytes, cipher: bitarray) -> bitarray:
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

    for _ in range(NB_ROUNDS):
        new_right = right ^ hash_half(sym_key, left)
        new_left = left ^ hash_half(sym_key, new_right)

        right = new_right
        left = new_left

    return new_left + new_right
