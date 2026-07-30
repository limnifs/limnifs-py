"""Slab reader — locates and extracts a drop's plaintext from a slab.

Mirrors ``limnifs-core::slab_reader``. Walks a slab's drop records
to derive the solid-window boundary (the v0.1 writer does not emit
an explicit ``drop_count``; the reader computes it from
``total_length - Σ len_in_window``). ``plaintext_for(drop_id)``
returns the decompressed bytes for a drop, supporting both store
(0x00) and LZ4 (0x01) codecs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from limnifs.codec import decompress
from limnifs.cursor import Cursor
from limnifs.drop_record import DROP_RECORD_LEN, DropRecord, parse_drop_record
from limnifs.error import CorruptError, UnsupportedFeatureError
from limnifs.slab_header import SlabHeader, parse_slab_header


@dataclass(slots=True)
class SlabView:
    """Parsed slab: header + drop records + view onto the solid window."""

    bytes_: bytes
    header: SlabHeader
    drop_records: list[DropRecord] = field(default_factory=list)
    solid_window_start: int = 0

    def find_record(self, drop_id: bytes) -> DropRecord | None:
        for record in self.drop_records:
            if record.drop_id.raw == drop_id:
                return record
        return None

    def plaintext_for(self, drop_id: bytes) -> tuple[bool, bytes | Exception | None]:
        """Return ``(True, plaintext)`` on success, ``(False, error)`` on
        unsupported representation, or ``(False, None)`` if the drop
        is not in this slab.

        Supports both store (0x00) and LZ4 (0x01) codecs. LZ4 drops
        are decompressed on read.
        """
        record = self.find_record(drop_id)
        if record is None:
            return False, None
        if record.representation.aead != 0x00:
            return False, UnsupportedFeatureError(
                f"drop aead 0x{record.representation.aead:02X} "
                "(only plaintext/0x00 supported in v0.1)"
            )
        if record.solid_window_index != 0:
            return False, UnsupportedFeatureError(
                f"solid_window_index {record.solid_window_index} "
                "(only single-window slabs supported in v0.1)"
            )
        start = self.solid_window_start + record.offset_in_window
        end = start + record.len_in_window
        if end > len(self.bytes_):
            return False, CorruptError(
                f"drop range [{start}..{end}] extends past slab length {len(self.bytes_)}"
            )
        try:
            plaintext = decompress(
                record.representation.codec,
                self.bytes_[start:end],
                record.plaintext_len,
            )
        except (CorruptError, UnsupportedFeatureError) as e:
            return False, e
        return True, plaintext


def parse_slab(data: bytes) -> SlabView:
    """Parse a slab into a :class:`SlabView` that exposes drop records
    and plaintext lookups.

    Walks every drop record to derive the solid-window boundary using
    ``len_in_window`` (the compressed/stored size). Supports both store
    and LZ4 codecs.
    """
    cursor = Cursor(data)
    header = parse_slab_header(cursor)
    if header.total_length != len(data):
        raise CorruptError(
            f"slab total_length {header.total_length} does not match buffer length {len(data)}"
        )

    drop_records: list[DropRecord] = []
    window_len_sum = 0
    while True:
        cursor_pos = cursor.position
        remaining_after_cursor = header.total_length - cursor_pos
        if remaining_after_cursor == window_len_sum:
            break
        if remaining_after_cursor < window_len_sum:
            raise CorruptError(
                f"slab drop records overran solid window: "
                f"cursor_pos={cursor_pos}, window_sum={window_len_sum}, "
                f"total_length={header.total_length}"
            )
        trailing = remaining_after_cursor - window_len_sum
        if trailing < DROP_RECORD_LEN:
            raise CorruptError(
                f"slab has {trailing} trailing bytes that are neither a full "
                "drop record nor accounted for by the solid window"
            )
        record = parse_drop_record(cursor, header)
        window_len_sum += record.len_in_window
        drop_records.append(record)

    solid_window_start = cursor.position
    return SlabView(
        bytes_=data,
        header=header,
        drop_records=drop_records,
        solid_window_start=solid_window_start,
    )