"""Metadata blob parser (spec §4.1 + §4.2).

The metadata blob is the layer-2 payload of a LimniFS image: every
inode and every directory node, packed contiguously. The
:mod:`limnifs.metadata_reference` section's ``inline_metadata`` field
(or the locators it carries) is the entry point; once the bytes are
in hand, this parser turns them into typed values.

Layout (v0.1)::

    +--------------------------------------------------+
    | inode_count    : u32 LE                           |  offset 0
    +--------------------------------------------------+
    | inodes[]       : inode_count x Inode             |  offset 4
    +--------------------------------------------------+
    | dir_node_count : u32 LE                           |  variable
    +--------------------------------------------------+
    | dir_nodes[]    : dir_node_count x DirectoryNode  |  variable
    +--------------------------------------------------+

The order within each list is the writer's choice. Readers MUST NOT
rely on a particular ordering; instead, they look up entries by
``inode_number`` or by ``btree_node_hash``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from limnifs.cursor import Cursor
from limnifs.directory_node import DirectoryNode, DirEntry, parse_directory_node
from limnifs.inode import DEFAULT_INLINE_DATA_MAX_BYTES, Inode, parse_inode
from limnifs.merkle import hash_section


@dataclass(slots=True, eq=True)
class MetadataBlob:
    """Parsed metadata blob."""

    inodes: list[Inode] = field(default_factory=list)
    dir_nodes: list[DirectoryNode] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.inodes) or bool(self.dir_nodes)

    def inode_by_number(self, number: int) -> Inode | None:
        for i in self.inodes:
            if i.number == number:
                return i
        return None

    def dir_node_by_hash(self, hash_: bytes) -> DirectoryNode | None:
        for node in self.dir_nodes:
            if dir_node_hash(node.entries) == hash_:
                return node
        return None

    def root_inode_number(self) -> int | None:
        """Identify the root directory's inode number.

        The root is the unique directory inode whose ``number`` is not
        referenced by any other directory's entries. Returns ``None``
        if there is no such inode or if more than one inode satisfies
        the criterion.
        """
        referenced: set[int] = set()
        for node in self.dir_nodes:
            for entry in node.entries:
                referenced.add(entry.inode_number)
        candidates = [
            i.number
            for i in self.inodes
            if i.is_directory and i.number not in referenced
        ]
        if len(candidates) == 1:
            return candidates[0]
        return None


def dir_node_hash(entries: list[DirEntry]) -> bytes:
    """Compute the BLAKE3 hash of a directory node's wire bytes.

    Same hash a directory inode's ``ContentHandle.Directory`` carries.
    """
    out = bytearray()
    out.append(1)  # version
    out += len(entries).to_bytes(4, "little")
    for entry in entries:
        name_bytes = entry.name.encode("utf-8")
        out += len(name_bytes).to_bytes(4, "little")
        out += name_bytes
        out += entry.inode_number.to_bytes(8, "little")
        out.append(entry.entry_type)
    return hash_section(bytes(out))


def parse_metadata_blob(
    cursor: Cursor,
    max_inline_bytes: int = DEFAULT_INLINE_DATA_MAX_BYTES,
) -> MetadataBlob:
    """Parse the metadata blob from the cursor's position."""
    inode_count = cursor.read_u32_le()
    inodes = [parse_inode(cursor, max_inline_bytes) for _ in range(inode_count)]
    dir_node_count = cursor.read_u32_le()
    dir_nodes = [parse_directory_node(cursor) for _ in range(dir_node_count)]
    return MetadataBlob(inodes=inodes, dir_nodes=dir_nodes)