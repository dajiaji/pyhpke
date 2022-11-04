from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey

from ..kem_key import KEMKeyPair
from ..kem_key_interface import KEMKeyInterface
from ..kem_primitives_interface import KEMPrimitivesInterface
from ..keys.x448_key import X448Key


class X448(KEMPrimitivesInterface):
    """ """

    def __init__(self):
        self._nsecret = 64

    def generate_key_pair(self) -> KEMKeyPair:
        sk = X448PrivateKey.generate()
        pk = sk.public_key()
        return KEMKeyPair(X448Key(sk), X448Key(pk))

    def derive_key_pair(self, ikm: bytes) -> KEMKeyPair:
        raise NotImplementedError()

    def deserialize_private_key(self, key: bytes) -> KEMKeyInterface:
        return X448Key.from_private_bytes(key)

    def serialize_public_key(self, pk: KEMKeyInterface) -> bytes:
        return pk.to_public_bytes()

    def deserialize_public_key(self, pk: bytes) -> KEMKeyInterface:
        return X448Key.from_public_bytes(pk)

    def derive_public_key(self, sk: KEMKeyInterface) -> KEMKeyInterface:
        return X448Key(sk.raw.public_key())

    def exchange(self, sk: KEMKeyInterface, pk: KEMKeyInterface) -> bytes:
        return sk.raw.exchange(pk.raw)
