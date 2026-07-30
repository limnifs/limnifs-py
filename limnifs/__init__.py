"""LimniFS Python reference reader.

Independent Python implementation of the LimniFS wire format, written
from the specification only. Never reads the Rust implementation; serves
as the spec-sufficiency oracle.

Public API:

- :class:`ManifestRoot`, :class:`DropId`, :class:`SlabId` -- identity types.
- :class:`ManifestHeader`, :class:`FeatureFlags`, :class:`MetadataReference`,
  :class:`SlabIndex`, :class:`History` -- parsed section types.
- :func:`parse_manifest` -- one-shot entry point that walks every required
  section and returns a :class:`Manifest`.
- :func:`compute_merkle_root` -- the image-identity primitive.
- :class:`ManifestBuilder` -- encoder for declarative specs (used by the
  test harness; not needed for read-only consumers).

Architecture mirrors the spec's section structure: one module per
section. The :class:`Cursor` centralises bounds checking so every
parser focuses on its own structural invariants.
"""

from __future__ import annotations

from limnifs.builder import ManifestArtifact, ManifestBuilder, ManifestSpec
from limnifs.cursor import Cursor
from limnifs.directory_node import (
    DIRECTORY_NODE_VERSION,
    DirectoryNode,
    DirEntry,
    EntryType,
    parse_directory_node,
)
from limnifs.error import ParseError
from limnifs.feature_flags import FeatureFlag, FeatureFlags, parse_feature_flags_section
from limnifs.format_types import DropId, ManifestRoot, Representation, SlabId, Tier
from limnifs.header import ManifestHeader, parse_manifest_header
from limnifs.history import History, HistoryEntry, HistoryOp, parse_history_section
from limnifs.inode import (
    DEFAULT_INLINE_DATA_MAX_BYTES,
    INODE_FIXED_PREFIX_LEN,
    INODE_FLAG_ATIME,
    INODE_FLAG_INLINE_DATA,
    INODE_FLAG_RESERVED_MASK,
    ContentHandle,
    ContentHandleKind,
    Inode,
    SliceRef,
    XAttr,
    parse_inode,
)
from limnifs.merkle import (
    MERKLE_DOMAIN_SEPARATOR,
    SectionHashes,
    compute_merkle_root,
    hash_empty_section,
    hash_section,
)
from limnifs.metadata import (
    MetadataBlob,
    dir_node_hash,
    parse_metadata_blob,
)
from limnifs.metadata_reference import MetadataReference, parse_metadata_reference_section
from limnifs.slab_index import SlabIndex, SlabIndexEntry, parse_slab_index_section

__all__ = [
    "DEFAULT_INLINE_DATA_MAX_BYTES",
    "DIRECTORY_NODE_VERSION",
    "INODE_FIXED_PREFIX_LEN",
    "INODE_FLAG_ATIME",
    "INODE_FLAG_INLINE_DATA",
    "INODE_FLAG_RESERVED_MASK",
    "MERKLE_DOMAIN_SEPARATOR",
    "ContentHandle",
    "ContentHandleKind",
    "Cursor",
    "DirEntry",
    "DirectoryNode",
    "DropId",
    "EntryType",
    "FeatureFlag",
    "FeatureFlags",
    "History",
    "HistoryEntry",
    "HistoryOp",
    "Inode",
    "ManifestArtifact",
    "ManifestBuilder",
    "ManifestHeader",
    "ManifestRoot",
    "ManifestSpec",
    "MetadataBlob",
    "MetadataReference",
    "ParseError",
    "Representation",
    "SectionHashes",
    "SlabId",
    "SlabIndex",
    "SlabIndexEntry",
    "SliceRef",
    "Tier",
    "XAttr",
    "compute_merkle_root",
    "dir_node_hash",
    "hash_empty_section",
    "hash_section",
    "parse_directory_node",
    "parse_feature_flags_section",
    "parse_history_section",
    "parse_inode",
    "parse_manifest_header",
    "parse_metadata_blob",
    "parse_metadata_reference_section",
    "parse_slab_index_section",
]
