"""Tests for the inode, directory_node, and metadata parsers."""

from __future__ import annotations

import pytest

from limnifs.cursor import Cursor
from limnifs.directory_node import (
    DIRECTORY_NODE_VERSION,
    DirEntry,
    EntryType,
    parse_directory_node,
)
from limnifs.error import CorruptError, TruncatedError, UnsupportedFeatureError
from limnifs.inode import (
    DEFAULT_INLINE_DATA_MAX_BYTES,
    INODE_FLAG_ATIME,
    INODE_FLAG_INLINE_DATA,
    S_IFDIR,
    S_IFREG,
    ContentHandleKind,
    parse_inode,
)
from limnifs.merkle import hash_section
from limnifs.metadata import (
    dir_node_hash,
    parse_metadata_blob,
)


def _encode_inode_inline(number: int, mode: int, data: bytes) -> bytes:
    """Encode a regular inline-file inode."""
    out = bytearray()
    out += number.to_bytes(8, "little")
    out += mode.to_bytes(4, "little")
    out += (0).to_bytes(4, "little")  # uid
    out += (0).to_bytes(4, "little")  # gid
    out += (0).to_bytes(8, "little")  # mtime
    out += (0).to_bytes(8, "little")  # ctime
    out += (1).to_bytes(4, "little")  # nlink
    out.append(INODE_FLAG_INLINE_DATA)
    out += len(data).to_bytes(4, "little")
    out += data
    return bytes(out)


def _encode_inode_directory(number: int, hash_: bytes) -> bytes:
    mode = S_IFDIR | 0o755
    out = bytearray()
    out += number.to_bytes(8, "little")
    out += mode.to_bytes(4, "little")
    out += (0).to_bytes(4, "little")  # uid
    out += (0).to_bytes(4, "little")  # gid
    out += (0).to_bytes(8, "little")  # mtime
    out += (0).to_bytes(8, "little")  # ctime
    out += (2).to_bytes(4, "little")  # nlink
    out.append(0)  # flags
    out += hash_
    return bytes(out)


def _encode_dir_node(entries: list[tuple[str, int, int]]) -> bytes:
    out = bytearray()
    out.append(DIRECTORY_NODE_VERSION)
    out += len(entries).to_bytes(4, "little")
    for name, inode_number, entry_type in entries:
        name_bytes = name.encode("utf-8")
        out += len(name_bytes).to_bytes(4, "little")
        out += name_bytes
        out += inode_number.to_bytes(8, "little")
        out.append(entry_type)
    return bytes(out)


def _encode_blob(inodes: list[bytes], dir_nodes: list[bytes]) -> bytes:
    out = bytearray()
    out += len(inodes).to_bytes(4, "little")
    for i in inodes:
        out += i
    out += len(dir_nodes).to_bytes(4, "little")
    for n in dir_nodes:
        out += n
    return bytes(out)


# --- inode ---


class TestInode:
    def test_parses_regular_inline_file(self) -> None:
        data = b"hello world"
        raw = _encode_inode_inline(42, S_IFREG | 0o644, data)
        inode = parse_inode(Cursor(raw))
        assert inode.number == 42
        assert inode.is_regular
        assert not inode.is_directory
        assert inode.atime_ns is None
        assert inode.xattrs == []
        assert inode.content_handle.kind is ContentHandleKind.INLINE_DATA
        assert inode.content_handle.inline_data == data

    def test_parses_directory(self) -> None:
        h = bytes([0xBB] * 32)
        raw = _encode_inode_directory(7, h)
        inode = parse_inode(Cursor(raw))
        assert inode.number == 7
        assert inode.is_directory
        assert inode.content_handle.kind is ContentHandleKind.DIRECTORY
        assert inode.content_handle.directory_hash == h

    def test_rejects_reserved_flag_bits(self) -> None:
        raw = bytearray(_encode_inode_inline(1, S_IFREG | 0o644, b"x"))
        raw[40] |= 0x08  # reserved bit
        with pytest.raises(CorruptError, match="reserved"):
            parse_inode(Cursor(bytes(raw)))

    def test_rejects_inline_above_ceiling(self) -> None:
        oversized = b"\xFF" * (DEFAULT_INLINE_DATA_MAX_BYTES + 1)
        raw = _encode_inode_inline(1, S_IFREG | 0o644, oversized)
        with pytest.raises(CorruptError, match="ceiling"):
            parse_inode(Cursor(raw))

    def test_parses_with_atime(self) -> None:
        mode = S_IFREG | 0o644
        out = bytearray()
        out += (1).to_bytes(8, "little")
        out += mode.to_bytes(4, "little")
        out += (0).to_bytes(4, "little")
        out += (0).to_bytes(4, "little")
        out += (0).to_bytes(8, "little")
        out += (0).to_bytes(8, "little")
        out += (1).to_bytes(4, "little")
        out.append(INODE_FLAG_ATIME)
        out += (999).to_bytes(8, "little")
        out += (0).to_bytes(4, "little")  # slice_count = 0
        inode = parse_inode(Cursor(bytes(out)))
        assert inode.atime_ns == 999


# --- directory node ---


class TestDirectoryNode:
    def test_parses_sorted_entries(self) -> None:
        raw = _encode_dir_node(
            [
                ("README.md", 3, EntryType.FILE),
                ("bin", 1, EntryType.DIRECTORY),
                ("hello.txt", 2, EntryType.FILE),
            ]
        )
        node = parse_directory_node(Cursor(raw))
        assert node.version == DIRECTORY_NODE_VERSION
        assert len(node.entries) == 3
        assert [e.name for e in node.entries] == ["README.md", "bin", "hello.txt"]

    def test_parses_empty_directory(self) -> None:
        raw = _encode_dir_node([])
        node = parse_directory_node(Cursor(raw))
        assert node.entries == []

    def test_rejects_unsorted_entries(self) -> None:
        raw = _encode_dir_node(
            [("z", 1, EntryType.FILE), ("a", 2, EntryType.FILE)]
        )
        with pytest.raises(CorruptError, match="not sorted"):
            parse_directory_node(Cursor(raw))

    def test_rejects_name_with_slash(self) -> None:
        raw = _encode_dir_node([("foo/bar", 1, EntryType.FILE)])
        with pytest.raises(CorruptError, match="'/"):
            parse_directory_node(Cursor(raw))

    def test_rejects_invalid_entry_type(self) -> None:
        out = bytearray()
        out.append(DIRECTORY_NODE_VERSION)
        out += (1).to_bytes(4, "little")
        out += (1).to_bytes(4, "little")  # name_len
        out += b"x"
        out += (1).to_bytes(8, "little")
        out.append(0x05)  # reserved
        with pytest.raises(CorruptError, match="invalid entry_type"):
            parse_directory_node(Cursor(bytes(out)))

    def test_rejects_unknown_node_version(self) -> None:
        raw = bytes([0x07]) + (0).to_bytes(4, "little")
        with pytest.raises(UnsupportedFeatureError, match="7"):
            parse_directory_node(Cursor(raw))


# --- metadata blob ---


class TestMetadataBlob:
    def test_parses_empty_blob(self) -> None:
        raw = _encode_blob([], [])
        blob = parse_metadata_blob(Cursor(raw))
        assert not blob
        assert blob.inodes == []
        assert blob.dir_nodes == []

    def test_parses_inline_inode(self) -> None:
        raw = _encode_blob([_encode_inode_inline(2, S_IFREG | 0o644, b"hi")], [])
        blob = parse_metadata_blob(Cursor(raw))
        assert len(blob.inodes) == 1
        assert blob.inodes[0].number == 2
        assert blob.inodes[0].content_handle.inline_data == b"hi"

    def test_parses_directory_with_node(self) -> None:
        node_bytes = _encode_dir_node([("a", 2, 0x01), ("b", 3, 0x01)])
        node_hash = hash_section(node_bytes)
        inode_bytes = _encode_inode_directory(1, node_hash)
        raw = _encode_blob([inode_bytes], [node_bytes])
        blob = parse_metadata_blob(Cursor(raw))
        assert len(blob.inodes) == 1
        assert len(blob.dir_nodes) == 1
        assert blob.inodes[0].is_directory

    def test_inode_lookup_by_number(self) -> None:
        raw = _encode_blob(
            [
                _encode_inode_inline(1, S_IFREG | 0o644, b"a"),
                _encode_inode_inline(2, S_IFREG | 0o644, b"b"),
            ],
            [],
        )
        blob = parse_metadata_blob(Cursor(raw))
        assert blob.inode_by_number(1) is not None
        assert blob.inode_by_number(2) is not None
        assert blob.inode_by_number(99) is None

    def test_root_inode_number_identifies_unique_root(self) -> None:
        # Root inode (1) is a directory, not referenced by any node.
        # Child inode (2) is referenced.
        child_node = _encode_dir_node([("a.txt", 2, 0x01)])
        child_hash = hash_section(child_node)
        root_inode = _encode_inode_directory(1, child_hash)
        child_inode = _encode_inode_inline(2, S_IFREG | 0o644, b"a")
        raw = _encode_blob([root_inode, child_inode], [child_node])
        blob = parse_metadata_blob(Cursor(raw))
        assert blob.root_inode_number() == 1

    def test_rejects_truncated_inode_count(self) -> None:
        with pytest.raises(TruncatedError):
            parse_metadata_blob(Cursor(b"\x00\x00"))

    def test_dir_node_hash_matches_writer_encoding(self) -> None:
        entries = [
            DirEntry(name="a.txt", inode_number=2, entry_type=0x01),
            DirEntry(name="b.txt", inode_number=3, entry_type=0x01),
        ]
        node_bytes = _encode_dir_node([("a.txt", 2, 0x01), ("b.txt", 3, 0x01)])
        assert dir_node_hash(entries) == hash_section(node_bytes)