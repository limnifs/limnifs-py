"""Directory node parser per spec §4.2 (bit-level/34-directory-node.md).

A directory node is a leaf of the deterministic Merkle B-tree that
represents a directory's entries. v0.1 defines a single layout: the
leaf node. Entries within a node MUST be lexicographic by name.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from limnifs.cursor import Cursor
from limnifs.error import CorruptError, UnsupportedFeatureError

#: Currently supported node version.
DIRECTORY_NODE_VERSION = 1


class EntryType:
    """POSIX-equivalent file-type tags used in directory entries."""

    FILE = 0x01
    DIRECTORY = 0x02
    SYMLINK = 0x03
    SPECIAL = 0x04

    @classmethod
    def is_valid(cls, value: int) -> bool:
        return value in (cls.FILE, cls.DIRECTORY, cls.SYMLINK, cls.SPECIAL)


@dataclass(slots=True, eq=True)
class DirEntry:
    """One directory entry: a name, an inode number, and a type tag."""

    name: str
    inode_number: int
    entry_type: int


@dataclass(slots=True, eq=True)
class DirectoryNode:
    """A parsed directory node (leaf only in v0.1)."""

    version: int
    entries: list[DirEntry] = field(default_factory=list)


def parse_directory_node(cursor: Cursor) -> DirectoryNode:
    """Parse one directory node from the cursor's position.

    Raises :class:`limnifs.error.ParseError` (subclass) on any
    structural problem (unsorted entries, empty names, names with
    ``/`` or NUL, invalid ``entry_type``, unknown node version).
    """
    version = cursor.read_u8()
    if version != DIRECTORY_NODE_VERSION:
        raise UnsupportedFeatureError(f"directory node version {version}")
    entry_count = cursor.read_u32_le()
    entries: list[DirEntry] = []
    prev_name: str | None = None
    for i in range(entry_count):
        name_len = cursor.read_u32_le()
        name_bytes = cursor.read(name_len)
        if not name_bytes:
            raise CorruptError(f"directory node entry {i}: empty name")
        if b"/" in name_bytes:
            raise CorruptError(
                f"directory node entry {i}: name contains '/'"
            )
        if b"\x00" in name_bytes:
            raise CorruptError(
                f"directory node entry {i}: name contains NUL byte"
            )
        try:
            name = name_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise CorruptError(
                f"directory node entry {i}: name is not valid UTF-8"
            ) from e
        if prev_name is not None and prev_name >= name:
            raise CorruptError(
                f"directory node: entries not sorted ({prev_name!r} >= {name!r})"
            )
        inode_number = cursor.read_u64_le()
        entry_type = cursor.read_u8()
        if not EntryType.is_valid(entry_type):
            raise CorruptError(
                f"directory node entry {i}: invalid entry_type 0x{entry_type:02X}"
            )
        prev_name = name
        entries.append(DirEntry(name=name, inode_number=inode_number, entry_type=entry_type))
    return DirectoryNode(version=version, entries=entries)