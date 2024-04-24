from bitarray import bitarray
from Crypto.Hash import SHA256
from kyber import Kyber1024

from .. import ideal_cipher
from .interlocutor_ocake import InterlocutorOCake


class AliceCake(InterlocutorOCake):
    def __init__(
        self,
        session_id: bytes,
        password: bytes,
        name: bytes = "Alice".encode("utf-8"),
        debug: bool = True,
    ) -> None:
        super().__init__(
            session_id=session_id,
            password=password,
            name=name,
            debug=debug,
        )

    def generate_keypair(self) -> None:
        self.public_key, self.secret_key = Kyber1024.keygen()
        self.encrypted_public_key = ideal_cipher.public_key.encrypt(
            self.public_key, self.derived_key
        )
        if self.debug:
            print(
                f"{self.name.decode('utf-8')} generated keypair: {self.public_key[:6].hex()}..."
            )
            print(
                f"{self.name.decode('utf-8')} encrypted public key: {self.encrypted_public_key[:12].to01()}..."
            )

    def decrypt_ciphertext(
        self, encrypted_ciphertext: bitarray, auth_verifier: bytes, bob_name: bytes
    ) -> None:
        self.encrypted_ciphertext = encrypted_ciphertext
        self.interlocutor_name = bob_name

        self.ciphertext = ideal_cipher.ciphertext.decrypt(
            self.encrypted_ciphertext, self.derived_key
        )

        if self.auth_verifier != auth_verifier:
            raise ValueError("Authentification failed. Key exchange aborted.")

        self.symmetric_key = Kyber1024.dec(self.ciphertext, self.secret_key)

        if self.debug:
            print(
                f"{self.name.decode('utf-8')} decrypted ciphertext: {self.ciphertext[:6].hex()}..."
            )
            print(
                f"{self.name.decode('utf-8')} derived symmetric key: {self.symmetric_key[:6].hex()}..."
            )
