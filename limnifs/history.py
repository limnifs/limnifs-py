"""History section parser per spec §5.9.

Append-only log of operations that derived this image. Every image
MUST have at least one history entry (the ``build`` op that
produced it).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from limnifs.cursor import Cursor
from limnifs.error import CorruptError, TruncatedError, UnsupportedFeatureError
from limnifs.format_types import ManifestRoot

#: Current layout version of this section.
HISTORY_SECTION_VERSION = 1

#: Default ceiling on the per-entry params blob length.
DEFAULT_HISTORY_PARAMS_MAX_BYTES = 4 * 1024

#: Sentinel value for op indicating an extended (post-v1) opcode.
OP_EXTENDED = 0xFF

#: Width of the fixed prefix of the section (version + u32 LE count).
PREFIX_LEN = 5

#: Width of the fixed prefix of each entry (op + timestamp + input_count).
ENTRY_FIXED_LEN = 1 + 8 + 4


class HistoryOp(IntEnum):
    """Operation kind per spec §5.9."""

    BUILD = 0x01
    DELTA = 0x02
    FLATTEN = 0x03
    TURNOVER = 0x04
    DEEPEN = 0x05

    @classmethod
    def from_byte(cls, byte: int) -> HistoryOp | None:
        try:
            return cls(byte)
        except ValueError:
            return None


@dataclass(slots=True, eq=True)
class HistoryEntry:
    """One history entry: operation plus inputs and parameters."""

    op: HistoryOp
    timestamp_ns: int
    inputs: list[ManifestRoot] = field(default_factory=list)
    params: bytes = b""


@dataclass(slots=True, eq=True)
class History:
    """Parsed history section."""

    entries: list[HistoryEntry] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.entries)

    def __bool__(self) -> bool:
        return bool(self.entries)


def parse_history_section(
    cursor: Cursor,
    max_params_bytes: int = DEFAULT_HISTORY_PARAMS_MAX_BYTES,
) -> History:
    """Parse the history section from the cursor's position."""
    section_version = cursor.read_u8()
    if section_version != HISTORY_SECTION_VERSION:
        raise UnsupportedFeatureError(
            f"history section version {section_version} "
            f"(supported: {HISTORY_SECTION_VERSION})"
        )
    raw_count = cursor.read_u32_le()
    entry_count = int(raw_count)
    if entry_count == 0:
        raise CorruptError(
            "history entry_count is 0 (every image must have at least the build entry)"
        )
    # DoS check: each entry needs at least ENTRY_FIXED_LEN + 4 bytes
    # (params_len field) before any inputs or params bodies.
    min_entry_width = ENTRY_FIXED_LEN + 4
    min_section_size = entry_count * min_entry_width
    if cursor.remaining_len < min_section_size:
        raise TruncatedError(have=cursor.remaining_len, need=min_section_size)
    entries: list[HistoryEntry] = []
    for index in range(entry_count):
        entry = _parse_history_entry(cursor, max_params_bytes, index)
        entries.append(entry)
    return History(entries=entries)


def _parse_history_entry(
    cursor: Cursor, max_params_bytes: int, index: int
) -> HistoryEntry:
    op_byte = cursor.read_u8()
    if op_byte == OP_EXTENDED:
        raise UnsupportedFeatureError(
            f"history entry {index}: op 0xFF (extended opcode, post-v1)"
        )
    op = HistoryOp.from_byte(op_byte)
    if op is None:
        raise UnsupportedFeatureError(
            f"history entry {index}: op 0x{op_byte:02X} is reserved (not in 0x01..0x05)"
        )
    timestamp_ns = cursor.read_u64_le()
    raw_input_count = cursor.read_u32_le()
    input_count = int(raw_input_count)
    inputs_size = input_count * 32
    if cursor.remaining_len < inputs_size:
        raise TruncatedError(have=cursor.remaining_len, need=inputs_size)
    inputs_bytes = cursor.read(inputs_size)
    inputs: list[ManifestRoot] = []
    for chunk_offset in range(0, inputs_size, 32):
        inputs.append(ManifestRoot(bytes_=inputs_bytes[chunk_offset:chunk_offset + 32]))
    params_len = cursor.read_u32_le()
    if params_len > max_params_bytes:
        raise CorruptError(
            f"history entry {index}: params_len {params_len} exceeds "
            f"ceiling {max_params_bytes}"
        )
    params = cursor.read(params_len)
    return HistoryEntry(
        op=op,
        timestamp_ns=timestamp_ns,
        inputs=inputs,
        params=params,
    )


__all__ = [
    "DEFAULT_HISTORY_PARAMS_MAX_BYTES",
    "ENTRY_FIXED_LEN",
    "HISTORY_SECTION_VERSION",
    "OP_EXTENDED",
    "PREFIX_LEN",
    "History",
    "HistoryEntry",
    "HistoryOp",
    "parse_history_section",
]
