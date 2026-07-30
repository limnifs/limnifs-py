"""Tests for the Cursor primitive."""

from __future__ import annotations

import pytest

from limnifs.cursor import Cursor
from limnifs.error import TruncatedError


def test_position_starts_at_zero() -> None:
    cursor = Cursor(b"\x00" * 32)
    assert cursor.position == 0
    assert cursor.remaining_len == 32


def test_read_u_advances_position() -> None:
    cursor = Cursor(b"\x42\x99")
    assert cursor.read_u8() == 0x42
    assert cursor.read_u8() == 0x99
    assert cursor.position == 2


def test_read_u16_le_little_endian() -> None:
    cursor = Cursor(b"\x34\x12")
    assert cursor.read_u16_le() == 0x1234


def test_read_u32_le_little_endian() -> None:
    cursor = Cursor(b"\x78\x56\x34\x12")
    assert cursor.read_u32_le() == 0x12345678


def test_read_u64_le_little_endian() -> None:
    cursor = Cursor(b"\xEF\xCD\xAB\x90\x78\x56\x34\x12")
    assert cursor.read_u64_le() == 0x1234567890ABCDEF


def test_read_n_returns_slice_and_advances() -> None:
    cursor = Cursor(bytes(range(6)))
    chunk = cursor.read(3)
    assert chunk == bytes([0, 1, 2])
    assert cursor.position == 3
    assert cursor.remaining == bytes([3, 4, 5])


def test_read_past_end_raises_truncated() -> None:
    cursor = Cursor(b"\x00\x00")
    cursor.skip(2)
    with pytest.raises(TruncatedError):
        cursor.read_u8()


def test_at_start_rejects_offset_past_end() -> None:
    with pytest.raises(TruncatedError):
        Cursor(b"\x00" * 3, pos=4)


def test_at_start_resumes_mid_buffer() -> None:
    cursor = Cursor(b"\x01\x02\x03\x04\x05", pos=2)
    assert cursor.position == 2
    assert cursor.read_u8() == 0x03
