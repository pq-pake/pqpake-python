from Crypto.Hash import SHA256

from ..interlocutor import Interlocutor


class InterlocutorCake(Interlocutor):
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
        return SHA256.new(
            self.session_id
            + first_name
            + second_name
            + self.encrypted_public_key
            + self.encrypted_ciphertext
            + self.symmetric_key
        ).digest()
