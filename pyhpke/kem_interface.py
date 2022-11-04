from typing import Optional, Tuple

from .consts import KEMId
from .kem_key_interface import KEMKeyInterface


class KEMInterface(object):
    """
    The KEM (Key Encapsulation Mechanism) interface.
    """

    @property
    def id(self) -> KEMId:
        """
        The KEM identifier.
        """
        raise NotImplementedError()

    def encap(self, pkr: KEMKeyInterface, sks: Optional[KEMKeyInterface] = None) -> Tuple[bytes, bytes]:
        raise NotImplementedError()

    def decap(self, enc: bytes, skr: KEMKeyInterface, pks: Optional[KEMKeyInterface] = None) -> bytes:
        raise NotImplementedError()
