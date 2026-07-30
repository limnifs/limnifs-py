"""Feature flags section parser per spec §5.2.

A list of ``(flag_id, required: bool)`` tuples. Each flag references
the feature-flag registry (§14). Required flags unknown to the
reader cause ``UnsupportedFeature``; optional flags are ignored (§18).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from limnifs.cursor import Cursor
from limnifs.error import CorruptError, UnsupportedFeatureError

#: Current layout version of the feature flags section.
FEATURE_FLAGS_SECTION_VERSION = 1

#: Width of the fixed prefix (version byte + u32 LE entry count).
PREFIX_LEN = 5

#: Width of a single entry (u16 LE flag id + u8 required).
ENTRY_LEN = 3


@dataclass(frozen=True, slots=True, eq=True)
class FeatureFlag:
    """One row of the feature flags section."""

    flag_id: int
    required: bool


@dataclass(slots=True, eq=True)
class FeatureFlags:
    """Parsed feature flags section, in wire order."""

    entries: list[FeatureFlag] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.entries)

    def __bool__(self) -> bool:
        return bool(self.entries)

    def get(self, flag_id: int) -> FeatureFlag | None:
        for entry in self.entries:
            if entry.flag_id == flag_id:
                return entry
        return None

    def is_required(self, flag_id: int) -> bool:
        entry = self.get(flag_id)
        return entry is not None and entry.required


def parse_feature_flags_section(cursor: Cursor) -> FeatureFlags:
    """Parse the feature flags section from the cursor's position."""
    section_version = cursor.read_u8()
    if section_version != FEATURE_FLAGS_SECTION_VERSION:
        raise UnsupportedFeatureError(
            f"feature_flags section version {section_version} "
            f"(supported: {FEATURE_FLAGS_SECTION_VERSION})"
        )
    raw_count = cursor.read_u32_le()
    entry_count = int(raw_count)
    # DoS check: each entry needs at least ENTRY_LEN bytes.
    if cursor.remaining_len < entry_count * ENTRY_LEN:
        from limnifs.error import TruncatedError
        raise TruncatedError(
            have=cursor.remaining_len,
            need=entry_count * ENTRY_LEN,
        )
    entries: list[FeatureFlag] = []
    seen: set[int] = set()
    for index in range(entry_count):
        flag_id = cursor.read_u16_le()
        if flag_id == 0:
            raise CorruptError(
                f"feature_flags entry {index}: flag_id 0x0000 is reserved"
            )
        required_byte = cursor.read_u8()
        if required_byte == 0x00:
            required = False
        elif required_byte == 0x01:
            required = True
        else:
            raise CorruptError(
                f"feature_flags entry {index}: required byte must be "
                f"0x00 or 0x01, got 0x{required_byte:02X}"
            )
        if flag_id in seen:
            raise CorruptError(
                f"feature_flags entry {index}: duplicate flag_id 0x{flag_id:04X}"
            )
        seen.add(flag_id)
        entries.append(FeatureFlag(flag_id=flag_id, required=required))
    return FeatureFlags(entries=entries)


__all__ = [
    "ENTRY_LEN",
    "FEATURE_FLAGS_SECTION_VERSION",
    "PREFIX_LEN",
    "FeatureFlag",
    "FeatureFlags",
    "parse_feature_flags_section",
]
