from bitarray import bitarray

from . import compact_encoder, feistel


NB_COEFFICIENTS = 1024
COEFFICIENT_MAX_VALUE = 3329

SEED_BYTES_LENGTH = 32
NB_FEISTEL_ITERATIONS = 10


encoder = compact_encoder.CompactEncoder(
    nb_coefficients=NB_COEFFICIENTS, coefficient_max_value=COEFFICIENT_MAX_VALUE
)


def encrypt(public_key: bytes, symmetric_key: bytes) -> bitarray:
    value_part = public_key[:-SEED_BYTES_LENGTH]
    seed_part = bitarray()
    seed_part.frombytes(public_key[-SEED_BYTES_LENGTH:])
    encoded_value_part = encoder.encode(value_part)
    value_being_encrypted = encoded_value_part
    encrypted_value_part = None
    for _ in range(NB_FEISTEL_ITERATIONS):
        value_being_encrypted = feistel.encrypt(symmetric_key, value_being_encrypted)
        if (
            sum(
                value_being_encrypted[-i - 1] << i
                for i in range(len(value_being_encrypted))
            )
            < COEFFICIENT_MAX_VALUE
            ** NB_COEFFICIENTS  # We test this first to improve timing attack mitigation.
            and encrypted_value_part is None
        ):
            encrypted_value_part = value_being_encrypted
    if encrypted_value_part is None:
        raise ValueError(
            f"Encryption could not be completed in {NB_FEISTEL_ITERATIONS} Feistel iterations."
        )
    return encrypted_value_part + feistel.encrypt(symmetric_key, seed_part)


def decrypt(encrypted_public_key: bitarray, symmetric_key: bytes) -> bytes:
    seed_part = feistel.decrypt(
        symmetric_key, encrypted_public_key[-SEED_BYTES_LENGTH * 8 :]
    ).tobytes()
    value_being_decrypted = encrypted_public_key[: -SEED_BYTES_LENGTH * 8]
    decrypted_value_part = None
    for _ in range(NB_FEISTEL_ITERATIONS):
        value_being_decrypted = feistel.decrypt(symmetric_key, value_being_decrypted)
        if (
            sum(
                value_being_decrypted[-i - 1] << i
                for i in range(len(value_being_decrypted))
            )
            < COEFFICIENT_MAX_VALUE**NB_COEFFICIENTS
            and decrypted_value_part is None
        ):
            decrypted_value_part = value_being_decrypted
        value_being_decrypted = feistel.decrypt(symmetric_key, value_being_decrypted)
    if decrypted_value_part is None:
        raise ValueError(
            f"Decryption could not be completed in {NB_FEISTEL_ITERATIONS} Feistel iterations."
        )
    return encoder.decode(decrypted_value_part) + seed_part
