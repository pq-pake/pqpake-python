from Crypto.Hash import SHA256

from ..interlocutor import Interlocutor


class InterlocutorOCake(Interlocutor):
    def __init__(
        self,
        session_id: bytes,
        password: bytes,
        name: bytes,
        debug: bool,
    ) -> None:
        super().__init__(
            session_id=session_id,
            password=password,
            name=name,
            debug=debug,
        )

    def _generate_session_key(self, first_name: bytes, second_name: bytes) -> bytes:
        if self.auth_verifier is None:
            raise ValueError("Auth verifier is not set")

        return SHA256.new(
            self.session_id
            + first_name
            + second_name
            + self.encrypted_public_key  # type: ignore
            + self.encrypted_ciphertext
            + self.auth_verifier
            + self.symmetric_key
        ).digest()

    @property
    def auth_verifier(self) -> bytes:
        if self.interlocutor_name is None:
            raise ValueError("Interlocutor name is not set")

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
            + self.encrypted_public_key  # type: ignore
            + self.encrypted_ciphertext
            + self.symmetric_key
        ).digest()
