"""EC params section parser per spec §5.6.

Optional Reed-Solomon erasure coding configuration. Present iff
the EC feature flag (``0x0001``) is declared in the feature flags.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from limnifs.cursor import Cursor
from limnifs.error import CorruptError, TruncatedError, UnsupportedFeatureError
from limnifs.format_types import SlabId

EC_PARAMS_SECTION_VERSION = 1
DEFAULT_EC_POLYNOMIAL = 0x011D
MAX_SHARDS = 255
OVERRIDE_ENTRY_LEN = 42


@dataclass(frozen=True, slots=True, eq=True)
class EcOverride:
    slab_id: SlabId
    k: int
    m: int


@dataclass(slots=True, eq=True)
class EcParams:
    k: int
    m: int
    polynomial: int
    overrides: list[EcOverride] = field(default_factory=list)


def _validate(k: int, m: int, label: str) -> None:
    if k < 1:
        raise CorruptError(f"ec_params {label}: k must be >= 1, got {k}")
    if m < 1:
        raise CorruptError(f"ec_params {label}: m must be >= 1, got {m}")
    if k + m > MAX_SHARDS:
        raise CorruptError(
            f"ec_params {label}: k + m = {k + m} exceeds GF(2^8) limit ({MAX_SHARDS})"
        )


def parse_ec_params_section(cursor: Cursor) -> EcParams:
    section_version = cursor.read_u8()
    if section_version != EC_PARAMS_SECTION_VERSION:
        raise UnsupportedFeatureError(
            f"ec_params section version {section_version} (supported: {EC_PARAMS_SECTION_VERSION})"
        )
    k = cursor.read_u8()
    m = cursor.read_u8()
    _validate(k, m, "default")
    polynomial = cursor.read_u16_le()
    if polynomial != DEFAULT_EC_POLYNOMIAL:
        raise UnsupportedFeatureError(
            f"ec_params polynomial 0x{polynomial:04X} (supported: 0x{DEFAULT_EC_POLYNOMIAL:04X})"
        )
    raw_count = cursor.read_u32_le()
    override_count = int(raw_count)
    min_size = override_count * OVERRIDE_ENTRY_LEN
    if cursor.remaining_len < min_size:
        raise TruncatedError(have=cursor.remaining_len, need=min_size)
    overrides: list[EcOverride] = []
    seen: set[tuple[int, bytes]] = set()
    for index in range(override_count):
        ordinal = cursor.read_u64_le()
        hash_ = cursor.read(32)
        slab_id = SlabId(ordinal=ordinal, hash_=hash_)
        ok = cursor.read_u8()
        om = cursor.read_u8()
        _validate(ok, om, f"override {index} for slab ordinal {ordinal}")
        key = (slab_id.ordinal, slab_id.hash_)
        if key in seen:
            raise CorruptError(
                f"ec_params override {index}: duplicate slab_id (ordinal {ordinal})"
            )
        seen.add(key)
        overrides.append(EcOverride(slab_id=slab_id, k=ok, m=om))
    return EcParams(k=k, m=m, polynomial=polynomial, overrides=overrides)
