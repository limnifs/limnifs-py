"""Manifest header parser per spec §5.1.

The first 16 bytes of every ``.lim`` image: magic ``LMFS``, three
independent u16 LE version fields, and 6 reserved bytes that MUST
be zero.
"""

from __future__ import annotations

from dataclasses import dataclass

from limnifs.cursor import Cursor
from limnifs.error import BadMagicError, CorruptError
from limnifs.format_types import MANIFEST_HEADER_LEN, MANIFEST_MAGIC

#: Current manifest header versions (all layers at version 1).
CURRENT_DROP_STORE_VERSION = 1
CURRENT_METADATA_VERSION = 1
CURRENT_MANIFEST_VERSION = 1


@dataclass(frozen=True, slots=True, eq=True)
class ManifestHeader:
    """Parsed 16-byte manifest header."""

    drop_store_version: int
    metadata_version: int
    manifest_version: int

    def to_bytes(self) -> bytes:
        from struct import pack
        return (
            MANIFEST_MAGIC
            + pack("<HHH", self.drop_store_version, self.metadata_version, self.manifest_version)
            + bytes(6)  # reserved
        )

    @classmethod
    def current(cls) -> ManifestHeader:
        return cls(
            drop_store_version=CURRENT_DROP_STORE_VERSION,
            metadata_version=CURRENT_METADATA_VERSION,
            manifest_version=CURRENT_MANIFEST_VERSION,
        )


def parse_manifest_header(cursor: Cursor) -> ManifestHeader:
    """Parse the manifest header from the cursor's current position.

    Advances the cursor by ``MANIFEST_HEADER_LEN`` bytes on success.
    """
    magic = cursor.read_magic()
    if magic != MANIFEST_MAGIC:
        raise BadMagicError(found=magic, expected=MANIFEST_MAGIC)
    drop_store_version = cursor.read_u16_le()
    metadata_version = cursor.read_u16_le()
    manifest_version = cursor.read_u16_le()
    reserved = cursor.read(6)
    if any(b != 0 for b in reserved):
        raise CorruptError(
            f"reserved bytes 10..16 must be zero, found {reserved.hex()}"
        )
    return ManifestHeader(
        drop_store_version=drop_store_version,
        metadata_version=metadata_version,
        manifest_version=manifest_version,
    )


__all__ = [
    "CURRENT_DROP_STORE_VERSION",
    "CURRENT_MANIFEST_VERSION",
    "CURRENT_METADATA_VERSION",
    "MANIFEST_HEADER_LEN",
    "ManifestHeader",
    "parse_manifest_header",
]
