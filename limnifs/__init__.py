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
from limnifs.codec import CODEC_LZ4, CODEC_STORE, compress, compress_lz4_with_size, decompress
from limnifs.cursor import Cursor
from limnifs.drop_record import DROP_RECORD_LEN, DropRecord, parse_drop_record
from limnifs.error import ParseError
from limnifs.feature_flags import FeatureFlag, FeatureFlags, parse_feature_flags_section
from limnifs.format_types import DropId, ManifestRoot, Representation, SlabId, Tier
from limnifs.header import ManifestHeader, parse_manifest_header
from limnifs.history import History, HistoryEntry, HistoryOp, parse_history_section
from limnifs.merkle import (
    MERKLE_DOMAIN_SEPARATOR,
    SectionHashes,
    compute_merkle_root,
    hash_empty_section,
    hash_section,
)
from limnifs.metadata_reference import MetadataReference, parse_metadata_reference_section
from limnifs.slab_header import (
    DEFAULT_SLAB_MAX_BYTES,
    SLAB_FORMAT_VERSION,
    SLAB_HEADER_LEN,
    SlabHeader,
    parse_slab_header,
)
from limnifs.slab_index import SlabIndex, SlabIndexEntry, parse_slab_index_section
from limnifs.slab_reader import SlabView, parse_slab

__all__ = [
    "CODEC_LZ4",
    "CODEC_STORE",
    "DEFAULT_SLAB_MAX_BYTES",
    "DROP_RECORD_LEN",
    "MERKLE_DOMAIN_SEPARATOR",
    "SLAB_FORMAT_VERSION",
    "SLAB_HEADER_LEN",
    "Cursor",
    "DropId",
    "DropRecord",
    "FeatureFlag",
    "FeatureFlags",
    "History",
    "HistoryEntry",
    "HistoryOp",
    "ManifestArtifact",
    "ManifestBuilder",
    "ManifestHeader",
    "ManifestRoot",
    "ManifestSpec",
    "MetadataReference",
    "ParseError",
    "Representation",
    "SectionHashes",
    "SlabHeader",
    "SlabId",
    "SlabIndex",
    "SlabIndexEntry",
    "SlabView",
    "Tier",
    "compress",
    "compress_lz4_with_size",
    "compute_merkle_root",
    "decompress",
    "hash_empty_section",
    "hash_section",
    "parse_drop_record",
    "parse_feature_flags_section",
    "parse_history_section",
    "parse_manifest_header",
    "parse_metadata_reference_section",
    "parse_slab",
    "parse_slab_header",
    "parse_slab_index_section",
]
