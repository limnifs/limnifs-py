"""Inode parser per spec §4.1 (bit-level/33-inode.md).

An inode represents one filesystem object. Every entry in the
directory tree references an inode by its number. The inode carries
POSIX attributes, optional xattrs, and a type-dependent content
handle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from limnifs.cursor import Cursor
from limnifs.error import CorruptError
from limnifs.format_types import DropId

#: Width of the fixed prefix (before optional atime / xattrs / content handle).
INODE_FIXED_PREFIX_LEN = 41

#: Flag: ``atime_ns`` field is present.
INODE_FLAG_ATIME = 0x01
#: Flag: xattr block is present.
INODE_FLAG_HAS_XATTRS = 0x02
#: Flag: inline data is present (regular files only).
INODE_FLAG_INLINE_DATA = 0x04
#: Mask for reserved flag bits (3-7).
INODE_FLAG_RESERVED_MASK = 0xF8

#: POSIX file type bits from ``mode``.
S_IFMT = 0xF000
S_IFREG = 0x8000
S_IFDIR = 0x4000
S_IFLNK = 0xA000
S_IFBLK = 0x6000
S_IFCHR = 0x2000
S_IFIFO = 0x1000
S_IFSOCK = 0xC000

#: Default inline-data ceiling (spec §4.3: threshold is spec-pinned).
DEFAULT_INLINE_DATA_MAX_BYTES = 4 * 1024


class ContentHandleKind(IntEnum):
    """Tag for the union discriminator derived from ``mode & S_IFMT``."""

    INLINE_DATA = 0
    SLICE_MAP = 1
    DIRECTORY = 2
    SYMLINK = 3
    DEVICE = 4
    PIPE = 5


@dataclass(slots=True, eq=True)
class XAttr:
    """One extended attribute."""

    namespace: int
    key: str
    value: bytes


@dataclass(slots=True, eq=True)
class SliceRef:
    """One entry in a slice map: maps a byte range of the file to a
    byte range of a drop's plaintext."""

    file_byte_start: int
    file_byte_end: int
    drop_id: DropId
    drop_byte_start: int
    drop_byte_len: int


@dataclass(slots=True, eq=True)
class ContentHandle:
    """Type-dependent content handle.

    Mirrors the Rust ``ContentHandle`` enum. The ``kind`` field is the
    discriminator; readers should match on it rather than testing
    which optional field is set.
    """

    kind: ContentHandleKind
    inline_data: bytes = b""
    slice_map: tuple[SliceRef, ...] = ()
    directory_hash: bytes = b""
    symlink_target: str = ""
    device_number: int = 0
    pipe_id: int = 0


@dataclass(slots=True, eq=True)
class Inode:
    """Parsed inode record."""

    number: int
    mode: int
    uid: int
    gid: int
    mtime_ns: int
    ctime_ns: int
    nlink: int
    content_handle: ContentHandle
    atime_ns: int | None = None
    xattrs: list[XAttr] = field(default_factory=list)

    @property
    def file_type(self) -> int:
        return self.mode & S_IFMT

    @property
    def is_regular(self) -> bool:
        return self.file_type == S_IFREG

    @property
    def is_directory(self) -> bool:
        return self.file_type == S_IFDIR


def parse_inode(cursor: Cursor, max_inline_bytes: int = DEFAULT_INLINE_DATA_MAX_BYTES) -> Inode:
    """Parse one inode record from the cursor's position.

    Raises :class:`limnifs.error.ParseError` (subclass) on any
    structural problem.
    """
    number = cursor.read_u64_le()
    mode = cursor.read_u32_le()
    uid = cursor.read_u32_le()
    gid = cursor.read_u32_le()
    mtime_ns = cursor.read_u64_le()
    ctime_ns = cursor.read_u64_le()
    nlink = cursor.read_u32_le()
    flags = cursor.read_u8()

    if flags & INODE_FLAG_RESERVED_MASK:
        raise CorruptError(f"inode {number}: reserved flag bits set (0x{flags:02X})")

    atime_ns: int | None = None
    if flags & INODE_FLAG_ATIME:
        atime_ns = cursor.read_u64_le()

    xattrs: list[XAttr] = []
    if flags & INODE_FLAG_HAS_XATTRS:
        xattrs = _parse_xattr_block(cursor)

    content_handle = _parse_content_handle(cursor, mode, flags, number, max_inline_bytes)

    return Inode(
        number=number,
        mode=mode,
        uid=uid,
        gid=gid,
        mtime_ns=mtime_ns,
        ctime_ns=ctime_ns,
        nlink=nlink,
        atime_ns=atime_ns,
        xattrs=xattrs,
        content_handle=content_handle,
    )


def _parse_xattr_block(cursor: Cursor) -> list[XAttr]:
    count = cursor.read_u32_le()
    out: list[XAttr] = []
    for _ in range(count):
        namespace = cursor.read_u8()
        if namespace > 0x03:
            raise CorruptError(
                f"xattr namespace 0x{namespace:02X} out of range (0x00..0x03)"
            )
        key_len = cursor.read_u32_le()
        key_bytes = cursor.read(key_len)
        try:
            key = key_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise CorruptError("xattr key is not valid UTF-8") from e
        if "\x00" in key:
            raise CorruptError("xattr key contains NUL byte")
        value_len = cursor.read_u32_le()
        value = cursor.read(value_len)
        out.append(XAttr(namespace=namespace, key=key, value=value))
    return out


def _parse_content_handle(
    cursor: Cursor,
    mode: int,
    flags: int,
    inode_number: int,
    max_inline_bytes: int,
) -> ContentHandle:
    file_type = mode & S_IFMT
    if file_type == S_IFREG:
        if flags & INODE_FLAG_INLINE_DATA:
            inline_len = cursor.read_u32_le()
            if inline_len > max_inline_bytes:
                raise CorruptError(
                    f"inode {inode_number}: inline_data_len {inline_len} "
                    f"exceeds ceiling {max_inline_bytes}"
                )
            data = cursor.read(inline_len)
            return ContentHandle(kind=ContentHandleKind.INLINE_DATA, inline_data=data)
        slice_count = cursor.read_u32_le()
        slices: list[SliceRef] = []
        for _ in range(slice_count):
            file_byte_start = cursor.read_u64_le()
            file_byte_end = cursor.read_u64_le()
            if file_byte_start >= file_byte_end:
                raise CorruptError(
                    f"inode {inode_number}: slice has file_byte_start "
                    f"({file_byte_start}) >= file_byte_end ({file_byte_end})"
                )
            drop_id_bytes = cursor.read(32)
            drop_id = DropId.from_bytes(drop_id_bytes)
            drop_byte_start = cursor.read_u32_le()
            drop_byte_len = cursor.read_u32_le()
            slices.append(
                SliceRef(
                    file_byte_start=file_byte_start,
                    file_byte_end=file_byte_end,
                    drop_id=drop_id,
                    drop_byte_start=drop_byte_start,
                    drop_byte_len=drop_byte_len,
                )
            )
        return ContentHandle(
            kind=ContentHandleKind.SLICE_MAP, slice_map=tuple(slices)
        )
    if file_type == S_IFDIR:
        hash_ = cursor.read(32)
        return ContentHandle(kind=ContentHandleKind.DIRECTORY, directory_hash=hash_)
    if file_type == S_IFLNK:
        target_len = cursor.read_u32_le()
        target_bytes = cursor.read(target_len)
        try:
            target = target_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise CorruptError("symlink target is not valid UTF-8") from e
        return ContentHandle(kind=ContentHandleKind.SYMLINK, symlink_target=target)
    if file_type in (S_IFBLK, S_IFCHR):
        dev = cursor.read_u64_le()
        return ContentHandle(kind=ContentHandleKind.DEVICE, device_number=dev)
    if file_type in (S_IFIFO, S_IFSOCK):
        pipe_id = cursor.read_u64_le()
        return ContentHandle(kind=ContentHandleKind.PIPE, pipe_id=pipe_id)
    raise CorruptError(
        f"inode {inode_number}: unknown file type 0x{file_type:04X}"
    )