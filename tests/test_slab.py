"""Tests for the slab header, drop record, and slab reader parsers."""

from __future__ import annotations

import pytest

from limnifs.cursor import Cursor
from limnifs.drop_record import parse_drop_record
from limnifs.error import BadMagicError, CorruptError, UnsupportedFeatureError
from limnifs.slab_header import (
    SLAB_FORMAT_VERSION,
    SLAB_HEADER_LEN,
    parse_slab_header,
)
from limnifs.slab_reader import parse_slab


def _make_slab(drops: list[tuple[bytes, bytes]]) -> bytes:
    """Build a slab with the given (drop_id, plaintext) pairs.

    Uses store codec, plaintext AEAD, no EC — matching the v0.1 writer.
    """
    drop_records = bytearray()
    solid_window = bytearray()
    for drop_id, plaintext in drops:
        plaintext_len = len(plaintext)
        offset_in_window = len(solid_window)
        drop_records.extend(drop_id)
        drop_records.extend(plaintext_len.to_bytes(4, "little"))
        drop_records.extend(bytes([0x00, 0x00, 0x00]))  # representation
        drop_records.append(0x00)  # solid_window_index
        drop_records.extend(offset_in_window.to_bytes(4, "little"))
        drop_records.extend(plaintext_len.to_bytes(4, "little"))
        solid_window.extend(plaintext)
    slab_content = bytes(drop_records) + bytes(solid_window)
    total_length = SLAB_HEADER_LEN + len(slab_content)
    out = bytearray()
    out.extend(b"LIM1")
    out.extend(SLAB_FORMAT_VERSION.to_bytes(2, "little"))
    out.extend((0).to_bytes(8, "little"))  # ordinal
    out.extend(bytes(32))  # hash
    out.extend(total_length.to_bytes(8, "little"))
    out.append(0x00)  # ec_descriptor
    out.append(0x00)  # crypto_hint
    out.extend(slab_content)
    return bytes(out)


class TestSlabHeader:
    def test_parses_plaintext_header(self) -> None:
        slab = _make_slab([])
        header = parse_slab_header(Cursor(slab))
        assert header.format_version == 1
        assert header.total_length == len(slab)
        assert not header.has_erasure_coding
        assert not header.is_sealed

    def test_rejects_bad_magic(self) -> None:
        slab = bytearray(_make_slab([]))
        slab[0:4] = b"XXXX"
        with pytest.raises(BadMagicError):
            parse_slab_header(Cursor(bytes(slab)))

    def test_rejects_unknown_format_version(self) -> None:
        slab = bytearray(_make_slab([]))
        slab[4:6] = (99).to_bytes(2, "little")
        with pytest.raises(UnsupportedFeatureError):
            parse_slab_header(Cursor(bytes(slab)))


class TestDropRecord:
    def test_parses_single_record(self) -> None:
        drop_id = bytes([0xAA] * 32)
        plaintext = b"hello world"
        slab = _make_slab([(drop_id, plaintext)])
        cursor = Cursor(slab)
        cursor.skip(SLAB_HEADER_LEN)
        header = parse_slab_header(Cursor(slab))
        record = parse_drop_record(cursor, header)
        assert record.drop_id.raw == drop_id
        assert record.plaintext_len == len(plaintext)
        assert record.representation.codec == 0x00
        assert record.representation.aead == 0x00
        assert record.solid_window_index == 0


class TestSlabReader:
    def test_parses_empty_slab(self) -> None:
        slab = _make_slab([])
        view = parse_slab(slab)
        assert len(view.drop_records) == 0

    def test_parses_single_drop(self) -> None:
        drop_id = bytes([0xAA] * 32)
        plaintext = b"hello world"
        slab = _make_slab([(drop_id, plaintext)])
        view = parse_slab(slab)
        assert len(view.drop_records) == 1
        ok, result = view.plaintext_for(drop_id)
        assert ok
        assert result == plaintext

    def test_parses_multiple_drops(self) -> None:
        id1 = bytes([0x11] * 32)
        id2 = bytes([0x22] * 32)
        id3 = bytes([0x33] * 32)
        p1 = b"first drop plaintext"
        p2 = b"second"
        p3 = b"third drop is longer than the others combined"
        slab = _make_slab([(id1, p1), (id2, p2), (id3, p3)])
        view = parse_slab(slab)
        assert len(view.drop_records) == 3
        for drop_id, plaintext in [(id1, p1), (id2, p2), (id3, p3)]:
            ok, result = view.plaintext_for(drop_id)
            assert ok
            assert result == plaintext

    def test_missing_drop_returns_false_none(self) -> None:
        drop_id = bytes([0xAA] * 32)
        slab = _make_slab([(drop_id, b"data")])
        view = parse_slab(slab)
        missing = bytes([0xBB] * 32)
        ok, result = view.plaintext_for(missing)
        assert not ok
        assert result is None

    def test_rejects_buffer_length_mismatch(self) -> None:
        drop_id = bytes([0xAA] * 32)
        slab = bytearray(_make_slab([(drop_id, b"data")]))
        slab_truncated = bytes(slab[:-1])
        with pytest.raises(CorruptError, match="does not match buffer length"):
            parse_slab(slab_truncated)

    def test_find_record_returns_none_for_missing(self) -> None:
        drop_id = bytes([0xAA] * 32)
        slab = _make_slab([(drop_id, b"data")])
        view = parse_slab(slab)
        missing = bytes([0xBB] * 32)
        assert view.find_record(missing) is None
        assert view.find_record(drop_id) is not None