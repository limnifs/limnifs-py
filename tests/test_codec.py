"""Tests for the codec module (store + LZ4)."""

from __future__ import annotations

import pytest

from limnifs.codec import CODEC_LZ4, CODEC_STORE, compress, compress_lz4_with_size, decompress
from limnifs.error import CorruptError, UnsupportedFeatureError


class TestStoreCodec:
    def test_compress_is_identity(self) -> None:
        data = b"hello world"
        assert compress(CODEC_STORE, data) == data

    def test_decompress_validates_length(self) -> None:
        data = b"hello world"
        assert decompress(CODEC_STORE, data, 11) == data

    def test_decompress_rejects_length_mismatch(self) -> None:
        with pytest.raises(CorruptError, match="does not match"):
            decompress(CODEC_STORE, b"hello world", 99)


class TestLZ4Codec:
    def test_round_trips(self) -> None:
        data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 10
        compressed = compress(CODEC_LZ4, data)
        decompressed = decompress(CODEC_LZ4, compressed, len(data))
        assert decompressed == data

    def test_compresses_repetitive_data(self) -> None:
        data = b"A" * 10_000
        compressed = compress(CODEC_LZ4, data)
        assert len(compressed) < len(data)

    def test_decompress_rejects_corrupt_input(self) -> None:
        with pytest.raises(CorruptError):
            decompress(CODEC_LZ4, b"\xff" * 100, 1000)

    def test_decompress_rejects_length_mismatch(self) -> None:
        data = b"test data"
        compressed = compress(CODEC_LZ4, data)
        with pytest.raises(CorruptError, match="does not match"):
            decompress(CODEC_LZ4, compressed, 999)


class TestUnknownCodec:
    def test_compress_rejects_unknown(self) -> None:
        with pytest.raises(UnsupportedFeatureError, match="0xFF"):
            compress(0xFF, b"data")

    def test_decompress_rejects_unknown(self) -> None:
        with pytest.raises(UnsupportedFeatureError, match="0xFF"):
            decompress(0xFF, b"data", 4)


class TestCompressLz4WithSize:
    def test_prepends_length(self) -> None:
        data = b"test data for lz4"
        compressed = compress_lz4_with_size(data)
        size = int.from_bytes(compressed[:4], "little")
        assert size == len(data)
