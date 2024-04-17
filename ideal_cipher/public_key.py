from bitarray import bitarray

from . import compact_encoder, feistel


NB_COEFFICIENTS = 1024
COEFFICIENT_MAX_VALUE = 3329

SEED_BYTES_LENGTH = 32


encoder = compact_encoder.CompactEncoder(
    nb_coefficients=NB_COEFFICIENTS, coefficient_max_value=COEFFICIENT_MAX_VALUE
)


def encrypt(public_key: bytes, symmetric_key: bytes) -> bitarray:
    value_part = public_key[:-SEED_BYTES_LENGTH]
    seed_part = bitarray()
    seed_part.frombytes(public_key[-SEED_BYTES_LENGTH:])
    encoded_value_part = encoder.encode(value_part)
    value_being_encrypted = feistel.encrypt(symmetric_key, encoded_value_part)
    while (
        sum(
            value_being_encrypted[-i - 1] << i
            for i in range(len(value_being_encrypted))
        )
        >= COEFFICIENT_MAX_VALUE**NB_COEFFICIENTS
    ):
        value_being_encrypted = feistel.encrypt(symmetric_key, value_being_encrypted)
    return value_being_encrypted + feistel.encrypt(symmetric_key, seed_part)


def decrypt(encrypted_public_key: bitarray, symmetric_key: bytes) -> bytes:
    seed_part = feistel.decrypt(
        symmetric_key, encrypted_public_key[-SEED_BYTES_LENGTH * 8 :]
    ).tobytes()
    key_being_decrypted = feistel.decrypt(
        symmetric_key, encrypted_public_key[: -SEED_BYTES_LENGTH * 8]
    )
    while (
        sum(key_being_decrypted[-i - 1] << i for i in range(len(key_being_decrypted)))
        >= COEFFICIENT_MAX_VALUE**NB_COEFFICIENTS
    ):
        key_being_decrypted = feistel.decrypt(symmetric_key, key_being_decrypted)
    return encoder.decode(key_being_decrypted) + seed_part
