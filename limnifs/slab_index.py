"""Slab index section parser per spec §5.4.

Per-slab table of contents: one entry per slab referenced by this
image. Each entry carries the ``SlabId`` and one or more locator
entries that can fetch the slab bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from limnifs.cursor import Cursor
from limnifs.error import CorruptError, TruncatedError, UnsupportedFeatureError
from limnifs.format_types import SlabId
from limnifs.locator import (
    DEFAULT_LOCATOR_MAX_URI_BYTES,
    LocatorEntry,
    parse_locator_entries,
)

#: Current layout version of this section.
SLAB_INDEX_SECTION_VERSION = 1

#: Width of the fixed prefix of the section (version + u32 LE count).
PREFIX_LEN = 5

#: Width of the SlabId + locator_count prefix of each entry.
ENTRY_FIXED_LEN = 40 + 4


@dataclass(slots=True, eq=True)
class SlabIndexEntry:
    """One slab index entry: SlabId plus its locators."""

    slab_id: SlabId
    locators: list[LocatorEntry] = field(default_factory=list)


@dataclass(slots=True, eq=True)
class SlabIndex:
    """Parsed slab index section."""

    entries: list[SlabIndexEntry] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.entries)

    def __bool__(self) -> bool:
        return bool(self.entries)

    def find(self, slab_id: SlabId) -> SlabIndexEntry | None:
        for entry in self.entries:
            if entry.slab_id == slab_id:
                return entry
        return None


def parse_slab_index_section(
    cursor: Cursor,
    max_locator_uri_bytes: int = DEFAULT_LOCATOR_MAX_URI_BYTES,
) -> SlabIndex:
    """Parse the slab index section from the cursor's position."""
    section_version = cursor.read_u8()
    if section_version != SLAB_INDEX_SECTION_VERSION:
        raise UnsupportedFeatureError(
            f"slab_index section version {section_version} "
            f"(supported: {SLAB_INDEX_SECTION_VERSION})"
        )
    raw_count = cursor.read_u32_le()
    entry_count = int(raw_count)
    # DoS check: each entry needs at least ENTRY_FIXED_LEN bytes.
    min_section_size = entry_count * ENTRY_FIXED_LEN
    if cursor.remaining_len < min_section_size:
        raise TruncatedError(have=cursor.remaining_len, need=min_section_size)
    entries: list[SlabIndexEntry] = []
    seen: set[tuple[int, bytes]] = set()
    for index in range(entry_count):
        ordinal = cursor.read_u64_le()
        hash_ = cursor.read(32)
        slab_id = SlabId(ordinal=ordinal, hash_=hash_)
        key = (slab_id.ordinal, slab_id.hash_)
        if key in seen:
            raise CorruptError(
                f"slab_index entry {index}: duplicate slab_id "
                f"(ordinal {slab_id.ordinal}, hash {slab_id.hash_.hex()})"
            )
        seen.add(key)
        locator_count = cursor.read_u32_le()
        if locator_count == 0:
            raise CorruptError(
                f"slab_index entry {index}: slab_id (ordinal {slab_id.ordinal}) "
                f"declares zero locators (unreachable)"
            )
        locators = parse_locator_entries(
            cursor, count=locator_count, max_uri_bytes=max_locator_uri_bytes
        )
        entries.append(SlabIndexEntry(slab_id=slab_id, locators=locators))
    return SlabIndex(entries=entries)


__all__ = [
    "ENTRY_FIXED_LEN",
    "PREFIX_LEN",
    "SLAB_INDEX_SECTION_VERSION",
    "SlabIndex",
    "SlabIndexEntry",
    "parse_slab_index_section",
]
