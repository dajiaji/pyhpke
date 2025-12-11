from .consts import KEMId
from .kem_key import KEMKeyPair
from .kem_key_interface import KEMKeyInterface


class KEMInterface:
    """
    The KEM (Key Encapsulation Mechanism) interface.
    """

    @property
    def id(self) -> KEMId:
        """
        The KEM identifier.
        """
        raise NotImplementedError()

    def deserialize_private_key(self, key: bytes) -> KEMKeyInterface:
        raise NotImplementedError()

    def deserialize_public_key(self, key: bytes) -> KEMKeyInterface:
        raise NotImplementedError()

    def encap(
        self, pkr: KEMKeyInterface, sks: KEMKeyInterface | None = None, eks: KEMKeyPair | None = None
    ) -> tuple[bytes, bytes]:
        raise NotImplementedError()

    def decap(self, enc: bytes, skr: KEMKeyInterface, pks: KEMKeyInterface | None = None) -> bytes:
        raise NotImplementedError()

    def derive_key_pair(self, ikm: bytes) -> KEMKeyPair:
        raise NotImplementedError()
