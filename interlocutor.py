from bitarray import bitarray
from Crypto.Hash import SHA512


class Interlocutor:
    def __init__(
        self,
        session_id: bytes,
        password: bytes,
        name: bytes,
        debug: bool,
    ) -> None:
        # The debug parameter is a boolean that indicates whether the Interlocutor should print debug messages.
        self.debug: bool = debug
        self.session_id: bytes = session_id
        self.password: bytes = password
        self.name: bytes = name

        # We create attributes for the upcoming keys and names that will be exchanged.
        self.interlocutor_name: bytes | None = None
        self.public_key: bytes | None = None
        self.secret_key: bytes | None = None
        self.encrypted_public_key: bitarray | None = None
        self.symmetric_key: bytes | None = None
        self.ciphertext: bytes | None = None
        self.encrypted_ciphertext: bitarray | None = None
        self._session_key: bytes | None = None

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
        if not self._session_key is None:
            return self._session_key

        if self.symmetric_key is None:
            raise ValueError("Kyber symmetric key is not set")

        if self.interlocutor_name is None:
            raise ValueError("Interlocutor name is not set")

        first_name: bytes = (
            self.name if self.name < self.interlocutor_name else self.interlocutor_name
        )
        second_name: bytes = (
            self.interlocutor_name if self.name < self.interlocutor_name else self.name
        )

        self._session_key = self._generate_session_key(first_name, second_name)

        return self._session_key

    def _generate_session_key(self, first_name: bytes, second_name: bytes) -> bytes:
        raise NotImplementedError
