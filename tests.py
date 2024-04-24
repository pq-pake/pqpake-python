from bitarray import bitarray
from Crypto.Random import get_random_bytes
from kyber import Kyber1024

from . import AliceCake, BobCake
from .ideal_cipher import feistel, public_key


def print_bytes(to_print: bytes, name: str, nbr_shown: int = 100) -> None:
    if nbr_shown * 2 > len(to_print):
        raise ValueError(
            "nbr_shown is too big compared to the size of the message to show."
        )

    print(
        f"{name}: {to_print.hex()[:nbr_shown//2]}...{to_print.hex()[-nbr_shown//2:]} [{len(to_print)} bytes]"
    )


def print_bits(to_print: bitarray, name: str, nbr_shown: int = 100) -> None:
    if nbr_shown * 2 > len(to_print):
        raise ValueError(
            "nbr_shown is too big compared to the size of the message to show."
        )

    print(
        f"{name}: {to_print.to01()[:nbr_shown//2]}...{to_print.to01()[-nbr_shown//2:]} [{len(to_print)} bits]"
    )


def feistel_test():
    initial_msg, final_msg = b"", b""
    while initial_msg == final_msg:
        symmetric_key = get_random_bytes(32)
        initial_msg = bitarray()
        initial_msg.frombytes(get_random_bytes(784 * 2 * 8))

        encrypted_msg = feistel.encrypt(symmetric_key, initial_msg)
        final_msg = feistel.decrypt(symmetric_key, encrypted_msg)

        print_bits(initial_msg, "Initial message  ")
        print_bits(encrypted_msg, "Encrypted message")
        print_bits(final_msg, "Decrypted message")

        print("initial_msg == final_msg:", initial_msg == final_msg)
        print("-" * 20)


def public_key_test():
    initial_public_key, final_public_key = b"", b""
    while initial_public_key == final_public_key:
        symmetric_key = get_random_bytes(32)
        initial_public_key, _ = Kyber1024.keygen()

        encrypted_public_key = public_key.encrypt(initial_public_key, symmetric_key)
        final_public_key = public_key.decrypt(encrypted_public_key, symmetric_key)

        print_bytes(initial_public_key, "Initial message  ")
        print_bits(encrypted_public_key, "Encrypted message")
        print_bytes(final_public_key, "Decrypted message")

        print(
            "initial_public_key == final_public_key:",
            initial_public_key == final_public_key,
        )
        print("-" * 20)


def cake_test():
    alice = AliceCake(int(0).to_bytes(), b"password123", debug=True)
    bob = BobCake(int(0).to_bytes(), b"password123", debug=True)

    alice.generate_keypair()
    bob.generate_symmetric_key(alice.encrypted_public_key, alice.name)  # type: ignore
    alice.decrypt_ciphertext(bob.encrypted_ciphertext, bob.name)  # type: ignore

    print(
        "alice.session_key == bob.session_key:",
        alice.session_key == bob.session_key,
    )


# feistel_test()
# public_key_test()
cake_test()
