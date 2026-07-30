"""Delta linkage section parser per spec §5.8.

Identifies this image as a delta against a parent image and records
the tree operations (Add/Remove/Replace) that transform the parent
tree. Absent for non-delta images.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from limnifs.cursor import Cursor
from limnifs.error import CorruptError, TruncatedError, UnsupportedFeatureError
from limnifs.format_types import ManifestRoot

DELTA_LINKAGE_SECTION_VERSION = 1
MIN_TREE_OP_LEN = 6


class TreeOpKind(IntEnum):
    ADD = 0x01
    REMOVE = 0x02
    REPLACE = 0x03

    @classmethod
    def from_byte(cls, byte: int) -> TreeOpKind | None:
        try:
            return cls(byte)
        except ValueError:
            return None

    @property
    def has_inode_number(self) -> bool:
        return self != TreeOpKind.REMOVE


@dataclass(slots=True, eq=True)
class TreeOp:
    kind: TreeOpKind
    path: str
    inode_number: int | None = None


@dataclass(slots=True, eq=True)
class DeltaLinkage:
    base_root: ManifestRoot
    tree_ops: list[TreeOp] = field(default_factory=list)


def parse_delta_linkage_section(cursor: Cursor) -> DeltaLinkage:
    section_version = cursor.read_u8()
    if section_version != DELTA_LINKAGE_SECTION_VERSION:
        raise UnsupportedFeatureError(
            f"delta_linkage section version {section_version} "
            f"(supported: {DELTA_LINKAGE_SECTION_VERSION})"
        )
    base_root_bytes = cursor.read(32)
    base_root = ManifestRoot(bytes_=base_root_bytes)
    raw_count = cursor.read_u32_le()
    op_count = int(raw_count)
    min_total = op_count * MIN_TREE_OP_LEN
    if cursor.remaining_len < min_total:
        raise TruncatedError(have=cursor.remaining_len, need=min_total)
    tree_ops: list[TreeOp] = []
    for index in range(op_count):
        op_byte = cursor.read_u8()
        if op_byte == 0xFF:
            raise UnsupportedFeatureError(
                f"delta_linkage tree_op {index}: op_type 0xFF (extended, post-v1)"
            )
        kind = TreeOpKind.from_byte(op_byte)
        if kind is None:
            raise UnsupportedFeatureError(
                f"delta_linkage tree_op {index}: op_type 0x{op_byte:02X} reserved"
            )
        path_len = cursor.read_u32_le()
        path_len_us = int(path_len)
        if path_len_us == 0:
            raise CorruptError(f"delta_linkage tree_op {index}: empty path")
        path_bytes = cursor.read(path_len_us)
        try:
            path = path_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise CorruptError(
                f"delta_linkage tree_op {index}: path not UTF-8"
            ) from e
        if "\0" in path:
            raise CorruptError(f"delta_linkage tree_op {index}: path contains NUL")
        if "//" in path:
            raise CorruptError(
                f"delta_linkage tree_op {index}: path has empty component (double-slash)"
            )
        inode_number = cursor.read_u64_le() if kind.has_inode_number else None
        tree_ops.append(TreeOp(kind=kind, path=path, inode_number=inode_number))
    return DeltaLinkage(base_root=base_root, tree_ops=tree_ops)
