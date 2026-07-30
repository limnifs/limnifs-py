"""Metadata reference section parser per spec §5.3.

Carries the BLAKE3 hash of the layer-2 metadata blob plus the
locators (or inline bytes) needed to fetch it. The Merkle root
(§5.10) commits to ``metadata_hash`` directly so swapping the
metadata blob invalidates the root.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from limnifs.cursor import Cursor
from limnifs.error import CorruptError, UnsupportedFeatureError
from limnifs.locator import (
    DEFAULT_LOCATOR_MAX_URI_BYTES,
    LocatorEntry,
    parse_locator_entries,
)

#: Current layout version of this section.
METADATA_REFERENCE_SECTION_VERSION = 1

#: Default ceiling on the inline metadata blob length (spec §5.3: 1 MiB).
DEFAULT_INLINE_METADATA_MAX_BYTES = 1024 * 1024


@dataclass(slots=True, eq=True)
class MetadataReference:
    """Parsed metadata reference section."""

    metadata_hash: bytes
    locators: list[LocatorEntry] = field(default_factory=list)
    inline_metadata: bytes | None = None

    def __post_init__(self) -> None:
        if len(self.metadata_hash) != 32:
            raise ValueError(
                f"metadata_hash must be 32 bytes, got {len(self.metadata_hash)}"
            )

    @property
    def is_inlined(self) -> bool:
        return self.inline_metadata is not None


def parse_metadata_reference_section(
    cursor: Cursor,
    max_locator_uri_bytes: int = DEFAULT_LOCATOR_MAX_URI_BYTES,
    max_inline_metadata_bytes: int = DEFAULT_INLINE_METADATA_MAX_BYTES,
) -> MetadataReference:
    """Parse the metadata reference section from the cursor's position."""
    section_version = cursor.read_u8()
    if section_version != METADATA_REFERENCE_SECTION_VERSION:
        raise UnsupportedFeatureError(
            f"metadata_reference section version {section_version} "
            f"(supported: {METADATA_REFERENCE_SECTION_VERSION})"
        )
    metadata_hash = cursor.read(32)
    locator_count = cursor.read_u32_le()
    locators = parse_locator_entries(
        cursor, count=locator_count, max_uri_bytes=max_locator_uri_bytes
    )
    inline_metadata_len = cursor.read_u32_le()
    inline_metadata: bytes | None = None
    if inline_metadata_len == 0:
        inline_metadata = None
    elif inline_metadata_len > max_inline_metadata_bytes:
        raise CorruptError(
            f"metadata_reference inline_metadata_len {inline_metadata_len} "
            f"exceeds ceiling {max_inline_metadata_bytes}"
        )
    else:
        inline_metadata = cursor.read(inline_metadata_len)
    if not locators and inline_metadata is None:
        raise CorruptError(
            "metadata_reference is unreachable: locator_count=0 and "
            "inline_metadata_len=0 (need at least one source)"
        )
    return MetadataReference(
        metadata_hash=metadata_hash,
        locators=locators,
        inline_metadata=inline_metadata,
    )


__all__ = [
    "DEFAULT_INLINE_METADATA_MAX_BYTES",
    "METADATA_REFERENCE_SECTION_VERSION",
    "MetadataReference",
    "parse_metadata_reference_section",
]
