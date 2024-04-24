from bitarray import bitarray
from Crypto.Hash import SHA256
from kyber import Kyber1024

from .. import ideal_cipher
from .interlocutor_ocake import InterlocutorOCake


class BobOCake(InterlocutorOCake):
    def __init__(
        self,
        session_id: bytes,
        password: bytes,
        name: bytes = "Bob".encode("utf-8"),
        debug: bool = True,
    ) -> None:
        super().__init__(
            session_id=session_id,
            password=password,
            name=name,
            debug=debug,
        )

    def generate_symmetric_key(
        self, encrypted_public_key: bitarray, alice_name: bytes
    ) -> None:
        self.encrypted_public_key = encrypted_public_key
        self.interlocutor_name = alice_name

        self.public_key = ideal_cipher.public_key.decrypt(
            self.encrypted_public_key, self.derived_key
        )
        self.ciphertext, self.symmetric_key = Kyber1024.enc(self.public_key)
        self.encrypted_ciphertext = ideal_cipher.ciphertext.encrypt(
            self.ciphertext, self.derived_key
        )

        if self.debug:
            print(
                f"{self.name.decode('utf-8')} decrypted public key: {self.public_key[:6].hex()}..."
            )
            print(
                f"{self.name.decode('utf-8')} generated symmetric key: {self.symmetric_key[:6].hex()}..."
            )
            print(
                f"{self.name.decode('utf-8')} encrypted ciphertext: {self.encrypted_ciphertext[:12].to01()}..."
            )
