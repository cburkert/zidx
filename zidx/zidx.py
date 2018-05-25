"""Z-IDX secure indexing scheme as presented by Goh"""

import math
import secrets
from typing import Tuple, List, Union

from BitVector import BitVector


HASH = "SHA256"
HASHLEN_BITS = 256


def keygen(fp_rate: float) -> Tuple[bytes, ...]:
    num_keys = _calc_num_keys(fp_rate)
    return tuple(secrets.token_bytes(HASHLEN_BITS // 8)
                 for _ in range(num_keys))


def _hmac(key: bytes, word: str) -> bytes:
    from hmac import HMAC
    return HMAC(key, word.encode(), HASH).digest()


def _calc_num_keys(fp_rate: float) -> int:
    return math.ceil(-1 * math.log2(fp_rate))


class Client(object):
    def __init__(self,
                 max_elements: int,
                 fp_rate: float,
                 key: Union[bytes, Tuple[bytes, ...]]) -> None:
        self.max_elements = max_elements
        self.fp_rate = fp_rate
        self.num_keys = _calc_num_keys(fp_rate)
        if isinstance(key, tuple):
            if len(key) != self.num_keys:
                raise ValueError("Number of keys does not match desired "
                                 "fp_rate. Should be %d." % self.num_keys)
        elif isinstance(key, bytes):
            key = self._derive_keys(key)
        else:
            raise TypeError("key should be either a tuple of sub-keys"
                            " or a master key in bytes")
        self.__keys = key

    def _derive_keys(self, master_key: bytes) -> Tuple[bytes, ...]:
        from hashlib import blake2b
        return tuple(
            blake2b(
                b'',
                digest_size=HASHLEN_BITS // 8,
                key=master_key,
                salt=str(subkeyid).encode(),
            ).digest() for subkeyid in range(self.num_keys)
        )

    def trapdoor(self, word: str) -> Tuple[bytes, ...]:
        return tuple(_hmac(key, word) for key in self.__keys)

    def partial_trapdoor(self, word: str) -> Tuple[bytes, ...]:
        """Randomly selects a subset of trapdoor to ofuscate query."""
        trap = self.trapdoor(word)
        random = secrets.SystemRandom()
        return tuple(random.sample(trap, len(trap) // 2))

    def buildIndex(self, docId: str, words: List[str]) -> 'Index':
        idx = Index(docId, self.max_elements, self.fp_rate)
        for word in words:
            trap = self.trapdoor(word)
            idx.add(trap)
        return idx

    def __repr__(self) -> str:
        return 'Client(%r, %r)' % (
            self.max_elements,
            self.fp_rate
        )


class Index(object):
    """Secure index for a document"""
    BYTEORDER = 'little'

    def __init__(self, docId: str, max_elements: int, fp_rate: float) -> None:
        self.docId = docId
        self.max_elements = max_elements
        self.fp_rate = fp_rate
        self.num_keys = _calc_num_keys(self.fp_rate)
        self.bf_size_bits = math.ceil((self.num_keys * max_elements) /
                                      math.log(2))
        self.__bf = BitVector(size=self.bf_size_bits)

    def codeword(self, trapdoor: Tuple[bytes, ...]) -> Tuple[bytes, ...]:
        return tuple(_hmac(x, self.docId) for x in trapdoor)

    def add(self, trapdoor: Tuple[bytes, ...]) -> None:
        for w in self.codeword(trapdoor):
            self.__bf[self.__get_bf_index(w)] = 1

    def __get_bf_index(self, key: bytes) -> int:
        return int.from_bytes(key, byteorder=self.BYTEORDER) % (
            self.bf_size_bits)

    def search(self, trapdoor: Tuple[bytes, ...]) -> bool:
        return all(self.__is_set(code) for code in self.codeword(trapdoor))

    def __is_set(self, key: bytes) -> bool:
        return self.__bf[self.__get_bf_index(key)] is 1

    def __contains__(self, trapdoor: Tuple[bytes, ...]) -> bool:
        return self.search(trapdoor)

    def blind(self, numwords: int) -> None:
        random = secrets.SystemRandom()
        for _ in range(numwords * self.num_keys):
            self.__bf[random.randrange(self.bf_size_bits)] = 1

    def __repr__(self) -> str:
        return 'Index(%r, %r, fp_rate=%r)' % (
            self.docId,
            self.max_elements,
            self.fp_rate
        )
