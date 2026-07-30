"""Merkle root construction per spec §5.10.

The ``ManifestRoot`` is the canonical image identity. Readers compute
it from the manifest's section bytes; the manifest does not store
its own root. The computation is a flat BLAKE3 over a 10-byte
domain separator followed by 10 section hashes (330 bytes total).
"""

from __future__ import annotations

from dataclasses import dataclass

from blake3 import blake3

from limnifs.format_types import ManifestRoot

#: 10-byte ASCII domain separator prepended to every Merkle root
#: computation. Prevents cross-protocol confusion.
MERKLE_DOMAIN_SEPARATOR = b"limnifs/v1"


def hash_section(buf: bytes) -> bytes:
    """Compute ``BLAKE3(buf)`` and return the 32-byte digest."""
    return blake3(buf).digest()


def hash_empty_section() -> bytes:
    """Compute ``BLAKE3(b"")`` -- the empty-section digest."""
    return hash_section(b"")


@dataclass(frozen=True, slots=True, eq=True)
class SectionHashes:
    """The 10 section-hash slots that feed into :func:`compute_merkle_root`."""

    metadata: bytes
    format_header: bytes
    feature_flags: bytes
    metadata_reference: bytes
    slab_index: bytes
    crypto_params: bytes
    ec_params: bytes
    dms_policy: bytes
    delta_linkage: bytes
    history: bytes

    def __post_init__(self) -> None:
        for name in (
            "metadata",
            "format_header",
            "feature_flags",
            "metadata_reference",
            "slab_index",
            "crypto_params",
            "ec_params",
            "dms_policy",
            "delta_linkage",
            "history",
        ):
            value = getattr(self, name)
            if len(value) != 32:
                raise ValueError(
                    f"SectionHashes.{name} must be 32 bytes, got {len(value)}"
                )


def compute_merkle_root(hashes: SectionHashes) -> ManifestRoot:
    """Compute the image's ``ManifestRoot`` from its 10 section hashes.

    Implements the flat-construction formula from spec §5.10:
    ``BLAKE3("limnifs/v1" || metadata || format_header || feature_flags
    || metadata_reference || slab_index || crypto_params || ec_params
    || dms_policy || delta_linkage || history)``. Total input width:
    10 + 10 x 32 = 330 bytes. Output: 32 bytes.
    """
    state = blake3()
    state.update(MERKLE_DOMAIN_SEPARATOR)
    state.update(hashes.metadata)
    state.update(hashes.format_header)
    state.update(hashes.feature_flags)
    state.update(hashes.metadata_reference)
    state.update(hashes.slab_index)
    state.update(hashes.crypto_params)
    state.update(hashes.ec_params)
    state.update(hashes.dms_policy)
    state.update(hashes.delta_linkage)
    state.update(hashes.history)
    return ManifestRoot(bytes_=state.digest())


def section_hashes_minimal(
    metadata: bytes,
    format_header: bytes,
    feature_flags: bytes,
    metadata_reference: bytes,
    slab_index: bytes,
    history: bytes,
) -> SectionHashes:
    """Construct a :class:`SectionHashes` for an image with all optional
    sections absent (crypto_params, ec_params, dms_policy, delta_linkage).

    Convenience for the common v0.1 plaintext non-delta case.
    """
    empty = hash_empty_section()
    return SectionHashes(
        metadata=metadata,
        format_header=format_header,
        feature_flags=feature_flags,
        metadata_reference=metadata_reference,
        slab_index=slab_index,
        crypto_params=empty,
        ec_params=empty,
        dms_policy=empty,
        delta_linkage=empty,
        history=history,
    )


__all__ = [
    "MERKLE_DOMAIN_SEPARATOR",
    "SectionHashes",
    "compute_merkle_root",
    "hash_empty_section",
    "hash_section",
    "section_hashes_minimal",
]
