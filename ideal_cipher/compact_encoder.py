from math import ceil, log2

from bitarray import bitarray
from kyber.utils import bytes_to_bits, bitstring_to_bytes


class CompactEncoder:
    """
    The role of this encoder is to convert a list of coefficients stored in
    bytes into a bitarray, and vice versa. The point with this encoding is to
    prevent any loss of space when storing the coefficients, so that no
    more than one bit is lost in total.
    For instance, the public key of Kyber1024 is composed of 1024 coefficients
    between 0 and 3328. If we were to store these coefficients in bytes, we
    would need 12 bits per coefficient, which would result in a total of 12288
    bits. With this encoding, we can store the coefficients in 11982 bits.
    """

    def __init__(self, nb_coefficients: int, coefficient_max_value: int) -> None:
        self.nb_coefficients = nb_coefficients
        self.coefficient_max_value = coefficient_max_value
        self.coefficient_bits = ceil(
            log2(coefficient_max_value)
        )  # Number of bits per coefficient in the initial encoding
        self.compacted_message_length = ceil(
            log2(coefficient_max_value**nb_coefficients)
        )  # Number of bits in the compacted message

    def encode(self, message: bytes) -> bitarray:
        coefficients = [0 for _ in range(self.nb_coefficients)]
        bits = bytes_to_bits(message)
        for i in range(self.nb_coefficients):
            coefficients[i] = sum(
                bits[i * self.coefficient_bits + j] << j
                for j in range(self.coefficient_bits)
            )
        associated_sum = 0
        for i in range(self.nb_coefficients):
            associated_sum += coefficients[i] * (self.coefficient_max_value ** (i))
        encoded_message = bitarray()
        encoded_message.frombytes(
            associated_sum.to_bytes(ceil(self.compacted_message_length / 8), "big")
        )
        return encoded_message[-self.compacted_message_length :]

    def decode(self, message: bitarray) -> bytes:
        associated_sum = sum(message[-i - 1] << i for i in range(len(message)))
        coefficients = [0 for _ in range(self.nb_coefficients)]
        for i in range(self.nb_coefficients):
            coefficients[i] = associated_sum % self.coefficient_max_value
            associated_sum //= self.coefficient_max_value
        bit_string = "".join(format(c, "012b")[::-1] for c in coefficients)
        return bitstring_to_bytes(bit_string)
