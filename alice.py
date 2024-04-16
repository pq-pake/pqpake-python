from kyber import Kyber1024
from bitarray import bitarray

from .interlocutor import Interlocutor
import ideal_cipher


class Alice(Interlocutor):
    def __init__(
        self,
        session_id: bytes,
        password: bytes,
        name: bytes = "Alice".encode("utf-8"),
        interlocutor_name: bytes = "Bob".encode("utf-8"),
        debug: bool = True,
    ) -> None:
        super().__init__(
            session_id=session_id,
            password=password,
            name=name,
            interlocutor_name=interlocutor_name,
            debug=debug,
        )

    def generate_keypair(self) -> None:
        self.public_key, self.secret_key = Kyber1024.keygen()
        self.encrypted_public_key = ideal_cipher.public_key.encrypt(self.public_key, self.derived_key)
        if self.debug:
            print(f"{self.name.decode("utf-8")} generated keypair: {self.public_key.hex()}")
            print(f"{self.name.decode("utf-8")} encrypted public key: {self.encrypted_public_key.hex()}")

    def decrypt_ciphertext(self, encrypted_ciphertext: bitarray) -> None:
        self.encrypted_ciphertext = encrypted_ciphertext
        self.ciphertext = ideal_cipher.ciphertext.decrypt(self.encrypted_ciphertext, self.derived_key)
        self.symmetric_key = Kyber1024.dec(self.ciphertext, self.secret_key)
        if self.debug:
            print(f"{self.name.decode("utf-8")} decrypted ciphertext: {self.ciphertext.hex()}")
            print(f"{self.name.decode("utf-8")} derived symmetric key: {self.symmetric_key.hex()}")
