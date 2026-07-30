"""Manifest builder: declarative spec → wire bytes + computed ``ManifestRoot``.

Each ``*Spec`` is a declarative description of one section. The
:class:`ManifestBuilder` encodes them in the spec's fixed section order
(header → feature flags → metadata reference → slab index → history
for v0.1 required sections; optional sections are absent and use
``BLAKE3(b"")`` in their Merkle slot).

This is the generator side of the conformance suite. It uses
:func:`limnifs.merkle.compute_merkle_root` to derive each vector's
expected ``ManifestRoot``. The parser side never shares code with
the encoder -- a bug in any parser surfaces as a mismatched field,
and a bug in the Merkle formula surfaces as a mismatched root.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from struct import pack
from typing import Literal

from limnifs.feature_flags import FEATURE_FLAGS_SECTION_VERSION
from limnifs.format_types import ManifestRoot, SlabId
from limnifs.history import HISTORY_SECTION_VERSION
from limnifs.merkle import (
    SectionHashes,
    compute_merkle_root,
    hash_empty_section,
    hash_section,
)
from limnifs.metadata_reference import METADATA_REFERENCE_SECTION_VERSION
from limnifs.slab_index import SLAB_INDEX_SECTION_VERSION


@dataclass(frozen=True, slots=True, eq=True)
class HeaderSpec:
    drop_store_version: int = 1
    metadata_version: int = 1
    manifest_version: int = 1


@dataclass(frozen=True, slots=True, eq=True)
class FeatureFlagSpec:
    flag_id: int
    required: bool


@dataclass(frozen=True, slots=True, eq=True)
class MetadataReferenceExternalSpec:
    """External metadata: hash + non-empty locator list."""

    metadata_hash: bytes
    locators: list[str]
    kind: Literal["external"] = "external"


@dataclass(frozen=True, slots=True, eq=True)
class MetadataReferenceInlinedSpec:
    """Inlined metadata: blob bytes; hash computed by the builder."""

    metadata: bytes
    kind: Literal["inlined"] = "inlined"


MetadataReferenceSpec = MetadataReferenceExternalSpec | MetadataReferenceInlinedSpec


@dataclass(frozen=True, slots=True, eq=True)
class SlabIndexEntrySpec:
    slab_id: SlabId
    locators: list[str]


class HistoryOpSpec(IntEnum):
    BUILD = 0x01
    DELTA = 0x02
    FLATTEN = 0x03
    TURNOVER = 0x04
    DEEPEN = 0x05


@dataclass(frozen=True, slots=True, eq=True)
class HistoryEntrySpec:
    op: HistoryOpSpec
    timestamp_ns: int = 0
    inputs: list[ManifestRoot] = field(default_factory=list)
    params: bytes = b""


@dataclass(slots=True, eq=True)
class ManifestSpec:
    """Declarative description of a complete v0.1 manifest."""

    header: HeaderSpec = field(default_factory=HeaderSpec)
    feature_flags: list[FeatureFlagSpec] = field(default_factory=list)
    metadata_reference: MetadataReferenceSpec | None = None
    slab_index: list[SlabIndexEntrySpec] = field(default_factory=list)
    history: list[HistoryEntrySpec] = field(default_factory=list)


@dataclass(slots=True, eq=True)
class ManifestArtifact:
    """Output of :meth:`ManifestBuilder.build`."""

    bytes_: bytes
    merkle_root: ManifestRoot
    section_hashes: SectionHashes


class ManifestBuilder:
    """Encodes a :class:`ManifestSpec` into wire bytes + ``ManifestRoot``."""

    def __init__(self, spec: ManifestSpec) -> None:
        if spec.metadata_reference is None:
            raise ValueError("ManifestSpec.metadata_reference is required")
        if not spec.history:
            raise ValueError("ManifestSpec.history must have at least one entry")
        self._spec = spec

    def build(self) -> ManifestArtifact:
        out = bytearray()

        header_start = len(out)
        self._encode_header(out)
        header_end = len(out)

        flags_start = len(out)
        self._encode_feature_flags(out)
        flags_end = len(out)

        meta_ref_start = len(out)
        metadata_hash = self._encode_metadata_reference(out)
        meta_ref_end = len(out)

        slab_index_start = len(out)
        self._encode_slab_index(out)
        slab_index_end = len(out)

        history_start = len(out)
        self._encode_history(out)
        history_end = len(out)

        section_hashes = SectionHashes(
            metadata=metadata_hash,
            format_header=hash_section(bytes(out[header_start:header_end])),
            feature_flags=hash_section(bytes(out[flags_start:flags_end])),
            metadata_reference=hash_section(bytes(out[meta_ref_start:meta_ref_end])),
            slab_index=hash_section(bytes(out[slab_index_start:slab_index_end])),
            crypto_params=hash_empty_section(),
            ec_params=hash_empty_section(),
            dms_policy=hash_empty_section(),
            delta_linkage=hash_empty_section(),
            history=hash_section(bytes(out[history_start:history_end])),
        )
        merkle_root = compute_merkle_root(section_hashes)
        return ManifestArtifact(
            bytes_=bytes(out),
            merkle_root=merkle_root,
            section_hashes=section_hashes,
        )

    def _encode_header(self, out: bytearray) -> None:
        h = self._spec.header
        out += b"LMFS"
        out += pack("<HHH", h.drop_store_version, h.metadata_version, h.manifest_version)
        out += bytes(6)  # reserved

    def _encode_feature_flags(self, out: bytearray) -> None:
        out.append(FEATURE_FLAGS_SECTION_VERSION)
        flags = self._spec.feature_flags
        out += pack("<I", len(flags))
        for flag in flags:
            out += pack("<H", flag.flag_id)
            out.append(1 if flag.required else 0)

    def _encode_metadata_reference(self, out: bytearray) -> bytes:
        out.append(METADATA_REFERENCE_SECTION_VERSION)
        spec = self._spec.metadata_reference
        assert spec is not None  # checked in __init__
        if isinstance(spec, MetadataReferenceInlinedSpec):
            metadata_hash = hash_section(spec.metadata)
            locators: list[str] = []
            inline_metadata: bytes | None = spec.metadata
        else:
            metadata_hash = spec.metadata_hash
            locators = list(spec.locators)
            inline_metadata = None
        out += metadata_hash
        out += pack("<I", len(locators))
        for uri in locators:
            _encode_locator(out, uri)
        if inline_metadata is None:
            out += pack("<I", 0)
        else:
            out += pack("<I", len(inline_metadata))
            out += inline_metadata
        return metadata_hash

    def _encode_slab_index(self, out: bytearray) -> None:
        out.append(SLAB_INDEX_SECTION_VERSION)
        entries = self._spec.slab_index
        out += pack("<I", len(entries))
        for entry in entries:
            out += entry.slab_id.to_bytes()
            out += pack("<I", len(entry.locators))
            for uri in entry.locators:
                _encode_locator(out, uri)

    def _encode_history(self, out: bytearray) -> None:
        out.append(HISTORY_SECTION_VERSION)
        entries = self._spec.history
        out += pack("<I", len(entries))
        for entry in entries:
            out.append(int(entry.op))
            out += pack("<Q", entry.timestamp_ns)
            out += pack("<I", len(entry.inputs))
            for input_root in entry.inputs:
                out += input_root.raw
            out += pack("<I", len(entry.params))
            out += entry.params


def _encode_locator(out: bytearray, uri: str) -> None:
    encoded = uri.encode("utf-8")
    out += pack("<I", len(encoded))
    out += encoded


__all__ = [
    "FeatureFlagSpec",
    "HeaderSpec",
    "HistoryEntrySpec",
    "HistoryOpSpec",
    "ManifestArtifact",
    "ManifestBuilder",
    "ManifestSpec",
    "MetadataReferenceExternalSpec",
    "MetadataReferenceInlinedSpec",
    "MetadataReferenceSpec",
    "SlabIndexEntrySpec",
]
