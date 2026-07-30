"""Cursor over a manifest byte buffer.

Centralises bounds checking and position tracking so every section
parser reads from the same abstraction. Parsers take a ``Cursor``
and advance it on success.

The cursor is a thin wrapper over ``bytes``; all accessors are
zero-cost after optimisation.
"""

from __future__ import annotations

from struct import unpack

from limnifs.error import CorruptError, TruncatedError


class Cursor:
    """A bounded cursor over a ``bytes`` buffer."""

    __slots__ = ("_buf", "_pos")

    def __init__(self, buf: bytes, pos: int = 0) -> None:
        if pos < 0 or pos > len(buf):
            raise TruncatedError(have=len(buf), need=pos)
        self._buf = buf
        self._pos = pos

    @property
    def position(self) -> int:
        return self._pos

    @property
    def remaining_len(self) -> int:
        return len(self._buf) - self._pos

    @property
    def remaining(self) -> bytes:
        return self._buf[self._pos:]

    def skip(self, n: int) -> None:
        """Advance past ``n`` bytes without inspecting them."""
        self.read(n)

    def read(self, n: int) -> bytes:
        """Read ``n`` bytes and advance."""
        if n < 0:
            raise CorruptError(f"negative read of {n} bytes")
        end = self._pos + n
        if end > len(self._buf):
            raise TruncatedError(have=self.remaining_len, need=n)
        chunk = self._buf[self._pos:end]
        self._pos = end
        return bytes(chunk)

    def read_u8(self) -> int:
        return self.read(1)[0]

    def read_u16_le(self) -> int:
        return unpack("<H", self.read(2))[0]

    def read_u32_le(self) -> int:
        return unpack("<I", self.read(4))[0]

    def read_u64_le(self) -> int:
        return unpack("<Q", self.read(8))[0]

    def read_magic(self) -> bytes:
        """Read exactly 4 bytes as a magic constant."""
        return self.read(4)
