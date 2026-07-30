"""Drop record parser per spec §3.3 (bit-level/31-drop-record.md).

One 48-byte descriptor per drop in a slab, locating the drop's bytes
inside one of the slab's solid windows.
"""

from __future__ import annotations

from dataclasses import dataclass

from limnifs.cursor import Cursor
from limnifs.error import CorruptError
from limnifs.format_types import DropId, Representation
from limnifs.slab_header import SlabHeader

#: Width of a single drop record on the wire.
DROP_RECORD_LEN = 48

#: Default per-drop plaintext-size ceiling.
DEFAULT_DROP_MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True, eq=True)
class DropRecord:
    """Parsed drop record."""

    drop_id: DropId
    plaintext_len: int
    representation: Representation
    solid_window_index: int
    offset_in_window: int
    len_in_window: int


def parse_drop_record(
    cursor: Cursor,
    slab: SlabHeader,
    max_plaintext: int = DEFAULT_DROP_MAX_PLAINTEXT_BYTES,
) -> DropRecord:
    """Parse a single drop record from the cursor's position."""
    drop_id_bytes = cursor.read(32)
    drop_id = DropId.from_bytes(drop_id_bytes)

    plaintext_len = cursor.read_u32_le()
    if plaintext_len > max_plaintext:
        raise CorruptError(
            f"drop plaintext_len {plaintext_len} exceeds ceiling {max_plaintext}"
        )

    rep_bytes = cursor.read(3)
    representation = Representation.from_bytes(rep_bytes)

    # Cross-field consistency: aead must be 0 in a plaintext slab;
    # ec must be 0 in a no-EC slab.
    if slab.crypto_hint == 0 and representation.aead != 0:
        raise CorruptError(
            f"drop aead 0x{representation.aead:02X} in plaintext slab (crypto_hint=0)"
        )
    if slab.ec_descriptor == 0 and representation.ec != 0:
        raise CorruptError(
            f"drop ec 0x{representation.ec:02X} in no-EC slab (ec_descriptor=0)"
        )

    solid_window_index = cursor.read_u8()
    offset_in_window = cursor.read_u32_le()
    len_in_window = cursor.read_u32_le()

    # Overflow check on offset + len.
    if offset_in_window + len_in_window < offset_in_window:
        raise CorruptError(
            f"drop offset_in_window ({offset_in_window}) + len_in_window ({len_in_window}) overflow"
        )

    return DropRecord(
        drop_id=drop_id,
        plaintext_len=plaintext_len,
        representation=representation,
        solid_window_index=solid_window_index,
        offset_in_window=offset_in_window,
        len_in_window=len_in_window,
    )