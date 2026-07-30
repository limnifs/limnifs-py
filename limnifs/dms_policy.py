"""DMS policy section parser per spec §5.7.

Optional Dead Man's Switch / key escrow record. v0.1 supports
Shamir k-of-n secret sharing only (time-lock deferred per §21.2).
Present iff the DMS feature flag (``0x0002``) is declared.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from limnifs.cursor import Cursor
from limnifs.error import CorruptError, UnsupportedFeatureError

DMS_POLICY_SECTION_VERSION = 1
DMS_SCHEME_SHAMIR = 0x00
DMS_SCHEME_EXTENDED = 0xFF
MAX_TOTAL_SHARES = 255
DEFAULT_SHARE_DATA_MAX_BYTES = 1024
DEFAULT_HINT_MAX_BYTES = 4 * 1024


@dataclass(slots=True, eq=True)
class ShareRecord:
    custodian_id: str
    share_data: bytes


@dataclass(slots=True, eq=True)
class DmsPolicy:
    k: int
    n: int
    shares: list[ShareRecord] = field(default_factory=list)
    reconstruction_hint: str | None = None


def parse_dms_policy_section(
    cursor: Cursor,
    max_share_data_bytes: int = DEFAULT_SHARE_DATA_MAX_BYTES,
    max_hint_bytes: int = DEFAULT_HINT_MAX_BYTES,
) -> DmsPolicy:
    section_version = cursor.read_u8()
    if section_version != DMS_POLICY_SECTION_VERSION:
        raise UnsupportedFeatureError(
            f"dms_policy section version {section_version} "
            f"(supported: {DMS_POLICY_SECTION_VERSION})"
        )
    scheme = cursor.read_u8()
    if scheme == DMS_SCHEME_EXTENDED:
        raise UnsupportedFeatureError(
            "dms_policy scheme 0xFF (extended descriptor, post-v1)"
        )
    if scheme != DMS_SCHEME_SHAMIR:
        raise UnsupportedFeatureError(
            f"dms_policy scheme 0x{scheme:02X} "
            f"(supported: 0x{DMS_SCHEME_SHAMIR:02X} Shamir)"
        )
    k = cursor.read_u8()
    n = cursor.read_u8()
    if k == 0:
        raise CorruptError("dms_policy k must be >= 1, got 0")
    if n == 0:
        raise CorruptError("dms_policy n must be >= 1, got 0")
    if k > n:
        raise CorruptError(f"dms_policy k ({k}) must be <= n ({n})")
    share_count = cursor.read_u32_le()
    if share_count != n:
        raise CorruptError(
            f"dms_policy share_count {share_count} does not equal n ({n})"
        )
    count_us = int(share_count)
    shares: list[ShareRecord] = []
    seen: set[str] = set()
    for index in range(count_us):
        cid_len = cursor.read_u32_le()
        if cid_len > max_hint_bytes:
            raise CorruptError(
                f"dms_policy custodian_id length {cid_len} exceeds ceiling {max_hint_bytes}"
            )
        cid_bytes = cursor.read(cid_len)
        try:
            cid = cid_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise CorruptError(f"dms_policy share {index}: custodian_id not UTF-8") from e
        if not cid:
            raise CorruptError(f"dms_policy share {index}: empty custodian_id")
        if cid in seen:
            raise CorruptError(f"dms_policy share {index}: duplicate custodian_id {cid!r}")
        seen.add(cid)
        sd_len = cursor.read_u32_le()
        if sd_len == 0:
            raise CorruptError(f"dms_policy share {index}: zero-length share_data")
        if sd_len > max_share_data_bytes:
            raise CorruptError(
                f"dms_policy share {index}: share_data_len {sd_len} exceeds ceiling {max_share_data_bytes}"
            )
        share_data = cursor.read(sd_len)
        shares.append(ShareRecord(custodian_id=cid, share_data=share_data))
    hint_len = cursor.read_u32_le()
    if hint_len == 0:
        hint = None
    elif hint_len > max_hint_bytes:
        raise CorruptError(
            f"dms_policy reconstruction_hint_len {hint_len} exceeds ceiling {max_hint_bytes}"
        )
    else:
        hint_bytes = cursor.read(hint_len)
        try:
            hint = hint_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise CorruptError("dms_policy reconstruction_hint not UTF-8") from e
    return DmsPolicy(k=k, n=n, shares=shares, reconstruction_hint=hint)
