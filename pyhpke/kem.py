import struct
from typing import Any, Optional, Tuple

from .consts import KDFId, KEMId
from .kdf import KDF
from .kem_interface import KEMInterface
from .kem_key import KEMKey, KEMKeyPair
from .kem_key_interface import KEMKeyInterface
from .kem_primitives.ec import EC
from .kem_primitives.x448 import X448
from .kem_primitives.x25519 import X25519


class KEM(KEMInterface):
    """
    The KEM (Key Encapsulation Mechanism) interface.
    """
    _nsecret: int

    def __init__(self, kem_id: KEMId):
        self._id = kem_id
        self._prim: Any
        if kem_id == KEMId.DHKEM_P256_HKDF_SHA256:
            self._nsecret = 32
            kdf_id = KDFId.HKDF_SHA256
            self._prim = EC(kem_id)
        elif kem_id == KEMId.DHKEM_P384_HKDF_SHA384:
            self._nsecret = 48
            kdf_id = KDFId.HKDF_SHA384
            self._prim = EC(kem_id)
        elif kem_id == KEMId.DHKEM_P521_HKDF_SHA512:
            kdf_id = KDFId.HKDF_SHA512
            self._nsecret = 64
            self._prim = EC(kem_id)
        elif kem_id == KEMId.DHKEM_X25519_HKDF_SHA256:
            kdf_id = KDFId.HKDF_SHA256
            self._nsecret = 32
            self._prim = X25519()
        elif kem_id == KEMId.DHKEM_X448_HKDF_SHA512:
            kdf_id = KDFId.HKDF_SHA512
            self._nsecret = 64
            self._prim = X448()
        else:
            raise ValueError("The specified kem is not supported.")
        suite_id = b"KEM" + struct.pack(">H", kem_id.value)
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

    def deserialize_private_key(self, key: bytes) -> KEMKeyInterface:
        return self._prim.deserialize_private_key(key)

    def deserialize_public_key(self, key: bytes) -> KEMKeyInterface:
        return self._prim.deserialize_public_key(key)

    def encap(
        self, pkr: KEMKeyInterface, sks: Optional[KEMKeyInterface] = None, eks: Optional[KEMKeyPair] = None
    ) -> Tuple[bytes, bytes]:
        """ """
        if eks is None:
            ek = self._prim.generate_key_pair()
        else:
            # For testing purpose only
            ek = eks
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

    def derive_key_pair(self, ikm: bytes):
        kdf = self._kdf
        old_nsecret = self._nsecret

        if self.id == KEMId.DHKEM_P256_HKDF_SHA256 or self.id == KEMId.DHKEM_P384_HKDF_SHA384:
            sk_raw = _ec_derive_key_pair(ikm, kdf, self)
        elif self.id == KEMId.DHKEM_P521_HKDF_SHA512:
            self._nsecret = 66
            sk_raw = _ec_derive_key_pair(ikm, kdf, self)
        elif self.id == KEMId.DHKEM_X25519_HKDF_SHA256:
            sk_raw = _x_derive_key_pair(ikm, kdf, self)
        elif self.id == KEMId.DHKEM_X448_HKDF_SHA512:
            self._nsecret = 56
            sk_raw = _x_derive_key_pair(ikm, kdf, self)
        else:
            raise ValueError("could not derive secret key")

        self._nsecret = old_nsecret

        # return the kemkeyinterface of the deserialized private key.
        private_key = self.deserialize_private_key(sk_raw)
        public_key = KEMKey.from_pyca_cryptography_key(private_key._key.public_key())

        return KEMKeyPair(private_key, public_key)


def _x_derive_key_pair(ikm: bytes, kdf: KDF, kem: KEM) -> bytes:
    # according to https://www.rfc-editor.org/rfc/rfc9180#section-7.1.3-9
    dkp_prk = kdf.labeled_extract(b"", b"dkp_prk", ikm)
    sk = kdf.labeled_expand(dkp_prk, b"sk", b"", kem._nsecret)
    return sk


def _ec_derive_key_pair(ikm: bytes, kdf: KDF, kem: KEM) -> bytes:
    # see https://www.rfc-editor.org/rfc/rfc9180#section-7.1.3-4

    dkp_prk = kdf.labeled_extract(b"", b"dkp_prk", ikm)
    match kem.id:
        case KEMId.DHKEM_P256_HKDF_SHA256:
            bitmask = 0xFF
            order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        case KEMId.DHKEM_P384_HKDF_SHA384:
            bitmask = 0xFF
            order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
        case KEMId.DHKEM_P521_HKDF_SHA512:
            bitmask = 0x01
            order = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
        case _:
            raise ValueError(f"Unknown KEMid {kem.id}")

    sk = 0
    counter = 0
    while sk == 0 or sk >= order:
        if counter > 255:
            raise ValueError("could not derive keypair")
        raw_key = bytearray(kdf.labeled_expand(dkp_prk, b"candidate", counter.to_bytes(1, "big"), kem._nsecret))

        raw_key[0] = raw_key[0] & bitmask
        sk = int.from_bytes(raw_key)
        counter = counter + 1
    return sk.to_bytes(kem._nsecret, "big", signed=False)
