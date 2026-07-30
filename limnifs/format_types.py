"""Semantic types: ``DropId``, ``SlabId``, ``ManifestRoot``, etc.

Mirrors ``limnifs-format`` from the Rust workspace. All types are
frozen dataclasses with ``slots=True`` for memory efficiency.
"""

from __future__ import annotations

from base64 import b32decode, b32encode
from dataclasses import dataclass
from enum import IntEnum
from struct import unpack
from typing import Self

BLAKE3_LEN = 32
ORDINAL_LEN = 8
SLAB_ID_LEN = ORDINAL_LEN + BLAKE3_LEN

#: Magic bytes ``b"LMFS"`` opening every manifest header (spec §5.1).
MANIFEST_MAGIC = b"LMFS"
#: Magic bytes ``b"LIM1"`` opening every slab header (spec §3.2).
SLAB_MAGIC = b"LIM1"
#: Width of the fixed manifest header.
MANIFEST_HEADER_LEN = 16


def _encode_base32_lower_nopad(data: bytes) -> str:
    """RFC 4648 base32 lowercase, no padding."""
    return b32encode(data).decode("ascii").rstrip("=").lower()


def _decode_base32_lower_nopad(text: str) -> bytes:
    """Inverse of :func:`_encode_base32_lower_nopad`."""
    pad = (-len(text)) % 8
    return b32decode(text.upper() + "=" * pad)


@dataclass(frozen=True, slots=True, eq=True)
class DropId:
    """``BLAKE3(plaintext)`` per spec §1.1. 32 bytes."""

    bytes_: bytes

    def __post_init__(self) -> None:
        if len(self.bytes_) != BLAKE3_LEN:
            raise ValueError(f"DropId must be {BLAKE3_LEN} bytes, got {len(self.bytes_)}")

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        return cls(bytes_=raw)

    @property
    def raw(self) -> bytes:
        return self.bytes_

    @classmethod
    def parse_text(cls, text: str) -> Self:
        if not text.startswith("b3:"):
            raise ValueError(f"DropId text must start with 'b3:', got {text!r}")
        decoded = _decode_base32_lower_nopad(text[3:])
        if len(decoded) != BLAKE3_LEN:
            raise ValueError(
                f"DropId text decoded to {len(decoded)} bytes, expected {BLAKE3_LEN}"
            )
        return cls(bytes_=decoded)

    def to_text(self) -> str:
        return "b3:" + _encode_base32_lower_nopad(self.bytes_)

    def __str__(self) -> str:
        return self.to_text()


@dataclass(frozen=True, slots=True, eq=True)
class ManifestRoot:
    """``BLAKE3`` of the Merkle hash list per spec §5.10. 32 bytes."""

    bytes_: bytes

    def __post_init__(self) -> None:
        if len(self.bytes_) != BLAKE3_LEN:
            raise ValueError(
                f"ManifestRoot must be {BLAKE3_LEN} bytes, got {len(self.bytes_)}"
            )

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        return cls(bytes_=raw)

    @property
    def raw(self) -> bytes:
        return self.bytes_

    def to_text(self) -> str:
        return "b3:" + _encode_base32_lower_nopad(self.bytes_)

    def __str__(self) -> str:
        return self.to_text()


@dataclass(frozen=True, slots=True, eq=True)
class SlabId:
    """Per-image slab identifier per spec §2.2.

    8-byte ordinal + 32-byte content hash; the ordinal distinguishes
    slabs that hash to the same value within one image.
    """

    ordinal: int
    hash_: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.ordinal < 2**64:
            raise ValueError(f"SlabId ordinal out of u64 range: {self.ordinal}")
        if len(self.hash_) != BLAKE3_LEN:
            raise ValueError(
                f"SlabId hash must be {BLAKE3_LEN} bytes, got {len(self.hash_)}"
            )

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        if len(raw) != SLAB_ID_LEN:
            raise ValueError(f"SlabId must be {SLAB_ID_LEN} bytes, got {len(raw)}")
        ordinal = unpack("<Q", raw[:ORDINAL_LEN])[0]
        hash_ = raw[ORDINAL_LEN:]
        return cls(ordinal=ordinal, hash_=hash_)

    def to_bytes(self) -> bytes:
        from struct import pack
        return pack("<Q", self.ordinal) + self.hash_


@dataclass(frozen=True, slots=True, eq=True)
class Representation:
    """Codec + AEAD + EC identifiers per spec §2.2 (3 bytes total)."""

    codec: int
    aead: int
    ec: int

    def __post_init__(self) -> None:
        for name, value in (("codec", self.codec), ("aead", self.aead), ("ec", self.ec)):
            if not 0 <= value < 256:
                raise ValueError(f"Representation.{name} out of u8 range: {value}")

    def to_bytes(self) -> bytes:
        return bytes([self.codec, self.aead, self.ec])

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        if len(raw) != 3:
            raise ValueError(f"Representation must be 3 bytes, got {len(raw)}")
        return cls(codec=raw[0], aead=raw[1], ec=raw[2])

    @property
    def is_plaintext(self) -> bool:
        return self.aead == 0x00

    @property
    def has_no_ec(self) -> bool:
        return self.ec == 0x00


#: Convenience constant for the store-codec, no-AEAD, no-EC representation.
REPRESENTATION_STORE_PLAINTEXT = Representation(codec=0x00, aead=0x00, ec=0x00)


class Tier(IntEnum):
    """Per-slab tier per spec §2.1."""

    EPILIMNION = 0x00
    METALIMNION = 0x01
    HYPOLIMNION = 0x02

    @classmethod
    def from_byte(cls, byte: int) -> Tier | None:
        try:
            return cls(byte)
        except ValueError:
            return None
