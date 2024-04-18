from Crypto.Hash import SHA512, SHA256
from bitarray import bitarray


class Interlocutor:
    def __init__(
        self,
        session_id: bytes,
        password: bytes,
        name: bytes,
        interlocutor_name: bytes,
        debug: bool,
    ) -> None:
        # The debug parameter is a boolean that indicates whether the Interlocutor should print debug messages.
        self.debug: bool = debug
        self.session_id: bytes = session_id
        self.password: bytes = password
        self.name: bytes = name
        self.interlocutor_name: bytes = interlocutor_name

        # We create attributes for the upcoming keys that will be exchanged.
        self.public_key: bytes | None = None
        self.secret_key: bytes | None = None
        self.encrypted_public_key: bitarray | None = None
        self.symmetric_key: bytes | None = None
        self.ciphertext: bytes | None = None
        self.encrypted_ciphertext: bitarray | None = None

        if self.debug:
            print(
                f"Interlocutor initialized with name {self.name.decode('utf-8')} "
                f"and password {self.password.decode('utf-8')}"
            )

    @property
    def derived_key(self):
        return SHA512.new(self.session_id + self.password).digest()

    @property
    def session_key(self) -> bytes:
        if self.symmetric_key is None:
            raise ValueError("Kyber symmetric key is not set")

        first_name: bytes = (
            self.name if self.name < self.interlocutor_name else self.interlocutor_name
        )
        second_name: bytes = (
            self.interlocutor_name if self.name < self.interlocutor_name else self.name
        )
        return SHA256.new(
            self.session_id
            + first_name
            + second_name
            + self.encrypted_public_key
            + self.encrypted_ciphertext
            + self.symmetric_key
        ).digest()

    def generate_keypair(self) -> None:
        raise NotImplementedError

    def generate_symmetric_key(self, encrypted_public_key: bitarray) -> None:
        raise NotImplementedError

    def decrypt_ciphertext(self, encrypted_ciphertext: bitarray) -> None:
        raise NotImplementedError
