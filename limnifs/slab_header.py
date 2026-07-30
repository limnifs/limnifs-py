"""Slab header parser per spec §3.2 (bit-level/30-slab-header.md).

The 56-byte fixed-size prefix at offset 0 of every slab in the drop
store. Magic ``LIM1``, u16 LE ``format_version``, ``SlabId``
(ordinal + hash), u64 LE ``total_length``, u8 ``ec_descriptor``,
u8 ``crypto_hint``.
"""

from __future__ import annotations

from dataclasses import dataclass

from limnifs.cursor import Cursor
from limnifs.error import BadMagicError, CorruptError, UnsupportedFeatureError
from limnifs.format_types import SLAB_MAGIC, SlabId

#: Default slab-size ceiling per §3.1 (64 MiB unless manifest overrides).
DEFAULT_SLAB_MAX_BYTES = 64 * 1024 * 1024

#: Current slab layout version (matches ``format_version`` byte 4..6).
SLAB_FORMAT_VERSION = 1

#: Width of the fixed slab header.
SLAB_HEADER_LEN = 56

#: Sentinel for extended ec_descriptor (post-v1).
EC_DESCRIPTOR_EXTENDED = 0xFF

#: Sentinel for extended crypto_hint (post-v1).
CRYPTO_HINT_EXTENDED = 0xFF


@dataclass(frozen=True, slots=True, eq=True)
class SlabHeader:
    """Parsed slab header."""

    format_version: int
    slab_id: SlabId
    total_length: int
    ec_descriptor: int
    crypto_hint: int

    @property
    def has_erasure_coding(self) -> bool:
        return self.ec_descriptor != 0x00 and self.ec_descriptor != EC_DESCRIPTOR_EXTENDED

    @property
    def is_sealed(self) -> bool:
        return self.crypto_hint != 0x00 and self.crypto_hint != CRYPTO_HINT_EXTENDED


def parse_slab_header(
    cursor: Cursor,
    max_total_length: int = DEFAULT_SLAB_MAX_BYTES,
) -> SlabHeader:
    """Parse a slab header from the cursor's position.

    Raises :class:`limnifs.error.ParseError` (subclass) on any
    structural problem.
    """
    magic = cursor.read_magic()
    if magic != SLAB_MAGIC:
        raise BadMagicError(found=magic, expected=SLAB_MAGIC)
    format_version = cursor.read_u16_le()
    if format_version != SLAB_FORMAT_VERSION:
        raise UnsupportedFeatureError(
            f"slab format_version {format_version} (supported: {SLAB_FORMAT_VERSION})"
        )
    slab_id_bytes = cursor.read(40)
    slab_id = SlabId.from_bytes(slab_id_bytes)
    total_length = cursor.read_u64_le()
    if total_length < SLAB_HEADER_LEN:
        raise CorruptError(
            f"slab total_length {total_length} is less than header width {SLAB_HEADER_LEN}"
        )
    if total_length > max_total_length:
        raise CorruptError(
            f"slab total_length {total_length} exceeds configured ceiling {max_total_length}"
        )
    ec_descriptor = cursor.read_u8()
    if ec_descriptor == EC_DESCRIPTOR_EXTENDED:
        raise UnsupportedFeatureError(
            "slab ec_descriptor 0xFF (extended descriptor, post-v1)"
        )
    crypto_hint = cursor.read_u8()
    if crypto_hint == CRYPTO_HINT_EXTENDED:
        raise UnsupportedFeatureError(
            "slab crypto_hint 0xFF (extended hint, post-v1)"
        )
    return SlabHeader(
        format_version=format_version,
        slab_id=slab_id,
        total_length=total_length,
        ec_descriptor=ec_descriptor,
        crypto_hint=crypto_hint,
    )