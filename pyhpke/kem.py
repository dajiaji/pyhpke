from typing import Any, Optional, Tuple

from .consts import KDFId, KEMId
from .kdf import KDF
from .kem_key_interface import KEMKeyInterface
from .kem_primitives.ec import EC
from .kem_primitives.x25519 import X25519
from .utils import i2osp


class KEM(object):
    """
    The KEM (Key Encapsulation Mechanism) interface.
    """

    def __init__(self, kem_id: KEMId, kdf_id: KDFId):

        self._id = kem_id
        self._prim: Any
        if kem_id == KEMId.DHKEM_P256_HKDF_SHA256:
            self._nsecret = 32
            self._prim = EC(kem_id)
        elif kem_id == KEMId.DHKEM_P384_HKDF_SHA384:
            self._nsecret = 48
            self._prim = EC(kem_id)
        elif kem_id == KEMId.DHKEM_P521_HKDF_SHA512:
            self._nsecret = 64
            self._prim = EC(kem_id)
        elif kem_id == KEMId.DHKEM_X25519_HKDF_SHA256:
            self._nsecret = 32
            self._prim = X25519()
        else:
            raise ValueError("The specified kem is not supported.")
        suite_id = b"KEM" + i2osp(kdf_id.value, 2)
        self._kdf = KDF(kdf_id, suite_id)
        return

    @property
    def id(self) -> KEMId:
        """
        The AEAD identifier.
        """
        return self._id

    def extract_and_expand(self, dh: bytes, kem_context: bytes, length: int) -> bytes:
        eae_prk = self._kdf.labeled_extract(b"", b"eae_prk", dh)
        shared_secret = self._kdf.labeled_expand(eae_prk, b"shared_secret", kem_context, length)
        return shared_secret

    def encap(self, pkr: KEMKeyInterface, sks: Optional[KEMKeyInterface] = None) -> Tuple[bytes, bytes]:
        """ """
        ek = self._prim.generate_key_pair()
        enc = self._prim.serialize_public_key(ek.public_key)

        if sks is None:
            dh = self._prim.exchange(ek.private_key, pkr)
            kem_context = enc + self._prim.serialize_public_key(pkr)
        else:
            dh1 = self._prim.exchange(ek.private_key, pkr)
            dh2 = self._prim.exchange(sks, pkr)
            dh = dh1 + dh2
            pks = self._prim.derive_public_key(sks)
            kem_context = enc + self._prim.serialize_public_key(pkr) + self._prim.serialize_public_key(pks)

        shared_secret = self.extract_and_expand(dh, kem_context, self._nsecret)
        return shared_secret, enc

    def decap(self, enc: bytes, skr: KEMKeyInterface, pks: Optional[KEMKeyInterface] = None) -> bytes:
        """ """
        pke = self._prim.deserialize_public_key(enc)
        pkr = self._prim.derive_public_key(skr)
        if pks is None:
            dh = self._prim.exchange(skr, pke)
            kem_context = enc + self._prim.serialize_public_key(pkr)
        else:
            dh1 = self._prim.exchange(skr, pke)
            dh2 = self._prim.exchange(skr, pks)
            dh = dh1 + dh2
            kem_context = enc + self._prim.serialize_public_key(pkr) + self._prim.serialize_public_key(pks)

        shared_secret = self.extract_and_expand(dh, kem_context, self._nsecret)
        return shared_secret
