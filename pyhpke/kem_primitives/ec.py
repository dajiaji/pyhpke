from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from ..consts import KEMId
from ..kem_key import KEMKeyPair
from ..kem_key_interface import KEMKeyInterface
from ..kem_primitives_interface import KEMPrimitivesInterface
from ..keys.ec_key import ECKey

# from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class EC(KEMPrimitivesInterface):
    """
    The KEM (Key Encapsulation Mechanism) context.
    """

    def __init__(self, kem_id: KEMId):
        if kem_id == KEMId.DHKEM_P256_HKDF_SHA256:
            self._crv = ec.SECP256R1()
            self._nsecret = 32
        elif kem_id == KEMId.DHKEM_P384_HKDF_SHA384:
            self._crv = ec.SECP384R1()
            self._nsecret = 48
        elif kem_id == KEMId.DHKEM_P521_HKDF_SHA512:
            self._crv = ec.SECP521R1()
            self._nsecret = 64
        else:
            raise ValueError(f"Invalid kem_id: {kem_id}")

    def generate_key_pair(self) -> KEMKeyPair:
        sk = ec.generate_private_key(self._crv, backend=default_backend())
        pk = sk.public_key()
        return KEMKeyPair(ECKey(sk), ECKey(pk))

    def derive_key_pair(self, ikm: bytes) -> KEMKeyPair:
        raise NotImplementedError()

    def deserialize_private_key(self, key: bytes) -> KEMKeyInterface:
        return ECKey.from_private_bytes(self._crv, key)

    def serialize_public_key(self, key: KEMKeyInterface) -> bytes:
        return key.to_public_bytes()

    def deserialize_public_key(self, key: bytes) -> KEMKeyInterface:
        return ECKey.from_public_bytes(self._crv, key)

    def derive_public_key(self, sk: KEMKeyInterface) -> KEMKeyInterface:
        return ECKey(sk.raw.public_key())

    def exchange(self, sk: KEMKeyInterface, pk: KEMKeyInterface) -> bytes:
        return sk.raw.exchange(ec.ECDH(), pk.raw)
