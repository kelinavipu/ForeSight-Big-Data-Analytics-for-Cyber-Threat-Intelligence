"""
High-performance and portable hashing utilities for Big Data algorithms.
Supports native mmh3 & bitarray with automatic pure-Python fallbacks.
"""

import hashlib
import struct

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

try:
    from bitarray import bitarray
    HAS_BITARRAY = True
except ImportError:
    HAS_BITARRAY = False


def py_murmur3_32(key: str, seed: int = 0) -> int:
    """Pure-Python implementation of 32-bit MurmurHash3."""
    if isinstance(key, str):
        data = key.encode("utf-8")
    else:
        data = bytes(key)

    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF

    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    # Body
    for i in range(nblocks):
        k1 = struct.unpack_from("<I", data, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    # Tail
    tail = data[nblocks * 4:]
    k1 = 0
    tail_len = len(tail)
    if tail_len >= 3:
        k1 ^= tail[2] << 16
    if tail_len >= 2:
        k1 ^= tail[1] << 8
    if tail_len >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    # Finalization
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    return h1 & 0xFFFFFFFF


def murmur3_32(key: str, seed: int = 0, signed: bool = False) -> int:
    """Computes MurmurHash3 32-bit integer."""
    if HAS_MMH3:
        val = mmh3.hash(key, seed, signed=signed)
        return val if signed else (val & 0xFFFFFFFF)
    val = py_murmur3_32(key, seed)
    if signed and val >= 0x80000000:
        return val - 0x100000000
    return val


def seeded_hash(key: str, seed: int = 0, max_val: int = 10_000_000) -> int:
    """Returns a deterministic pseudo-random hash in [0, max_val)."""
    return murmur3_32(key, seed, signed=False) % max_val


class SimpleBitArray:
    """Portable bit array implementation with O(1) bit access."""
    def __init__(self, size: int):
        self.size = size
        self._bytes = bytearray((size + 7) // 8)

    def setall(self, value: int):
        fill = 0xFF if value else 0x00
        for i in range(len(self._bytes)):
            self._bytes[i] = fill

    def __getitem__(self, index: int) -> int:
        if index < 0 or index >= self.size:
            raise IndexError("Bit index out of range")
        byte_idx = index >> 3
        bit_idx = index & 7
        return (self._bytes[byte_idx] >> bit_idx) & 1

    def __setitem__(self, index: int, value: int):
        if index < 0 or index >= self.size:
            raise IndexError("Bit index out of range")
        byte_idx = index >> 3
        bit_idx = index & 7
        if value:
            self._bytes[byte_idx] |= (1 << bit_idx)
        else:
            self._bytes[byte_idx] &= ~(1 << bit_idx)

    def count(self, value: int = 1) -> int:
        total_ones = sum(bin(b).count('1') for b in self._bytes)
        return total_ones if value == 1 else (self.size - total_ones)

    def buffer_info(self):
        return (len(self._bytes), len(self._bytes))


def create_bitarray(size: int):
    """Creates a bitarray instance using C-extension if available, else SimpleBitArray."""
    if HAS_BITARRAY:
        bits = bitarray(size)
        bits.setall(0)
        return bits
    bits = SimpleBitArray(size)
    bits.setall(0)
    return bits
