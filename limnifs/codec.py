"""Codec registry — dispatches compression/decompression by codec id.

Mirrors ``limnifs-core::codec``. Each drop record carries a
``representation`` triple (codec, aead, ec). This module centralises
the codec dispatch so the slab reader and the deepening stage share a
single source of truth.

Supported codecs (v0.1):

- ``0x00`` store: no compression; bytes are plaintext
- ``0x01`` lz4: LZ4 block format with size prefix
"""

from __future__ import annotations

import lz4.block

from limnifs.error import CorruptError, UnsupportedFeatureError

# Codec id 0x00: store (no compression).
CODEC_STORE = 0x00
# Codec id 0x01: LZ4 block format.
CODEC_LZ4 = 0x01


class CodecError(Exception):
    """Base for codec dispatch errors."""


def compress(codec_id: int, plaintext: bytes) -> bytes:
    """Compress ``plaintext`` using the codec identified by ``codec_id``.

    For ``CODEC_STORE`` the input is returned unchanged. For
    ``CODEC_LZ4`` the input is compressed with the LZ4 block format
    using size-prepend mode (the 4-byte LE original length prefix
    that the Rust ``lz4_flex::compress_prepend_size`` produces).
    """
    if codec_id == CODEC_STORE:
        return plaintext
    if codec_id == CODEC_LZ4:
        block = lz4.block.compress(plaintext, store_size=False)
        return len(plaintext).to_bytes(4, "little") + block
    raise UnsupportedFeatureError(f"compress codec 0x{codec_id:02X}")


def decompress(codec_id: int, compressed: bytes, expected_len: int) -> bytes:
    """Decompress ``compressed`` using the codec identified by ``codec_id``.

    The ``expected_len`` is the plaintext_len from the drop record; the
    decompressed output MUST match it exactly.
    """
    if codec_id == CODEC_STORE:
        actual = len(compressed)
        if actual != expected_len:
            raise CorruptError(
                f"store codec: compressed length {actual} does not match plaintext_len {expected_len}"
            )
        return compressed
    if codec_id == CODEC_LZ4:
        if len(compressed) < 4:
            raise CorruptError("lz4: compressed data too short for size prefix")
        # The Rust writer (lz4_flex::compress_prepend_size) prepends a
        # 4-byte LE original-length header. Python's lz4.block doesn't
        # auto-read this prefix via uncompressed_size=0, so we skip it
        # manually and pass the explicit expected size.
        try:
            result = lz4.block.decompress(compressed[4:], uncompressed_size=expected_len)
        except Exception as e:
            raise CorruptError(f"lz4 decompress failed: {e}") from e
        if len(result) != expected_len:
            raise CorruptError(
                f"lz4 decompress: result length {len(result)} does not match "
                f"plaintext_len {expected_len}"
            )
        return result
    raise UnsupportedFeatureError(f"decompress codec 0x{codec_id:02X}")


def compress_lz4_with_size(plaintext: bytes) -> bytes:
    """Compress with LZ4, prepending the original size as a 4-byte LE
    header."""
    return compress(CODEC_LZ4, plaintext)


__all__ = [
    "CODEC_LZ4",
    "CODEC_STORE",
    "CodecError",
    "compress",
    "compress_lz4_with_size",
    "decompress",
]