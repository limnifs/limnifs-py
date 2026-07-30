"""Locator entry parser per spec §12 / bit-level/37-locator-entry.md.

Each locator is a length-prefixed URI in the
``scheme ":" scheme_specific_part`` form. The parser does NOT enforce
scheme-implementedness -- that policy lives at the locator-racing
layer (§I9).
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from limnifs.cursor import Cursor
from limnifs.error import CorruptError, TruncatedError, UnsupportedFeatureError

#: Width of the u32 LE length prefix on every locator entry.
LOCATOR_LENGTH_PREFIX_LEN = 4

#: Default per-locator URI byte ceiling.
DEFAULT_LOCATOR_MAX_URI_BYTES = 4 * 1024

#: Smallest meaningful URI: one-letter scheme plus ``://``.
MIN_LOCATOR_URI_BYTES = 4


@dataclass(frozen=True, slots=True, eq=True)
class LocatorEntry:
    """A parsed locator entry."""

    uri: str

    @property
    def scheme(self) -> str | None:
        parse = urlparse(self.uri)
        return parse.scheme or None

    @property
    def scheme_specific_part(self) -> str | None:
        parse = urlparse(self.uri)
        if not parse.scheme:
            return None
        # Strip the leading scheme + ':' so callers see just the rest.
        return self.uri[len(parse.scheme) + 1:]


def _is_valid_scheme(scheme: str) -> bool:
    """RFC 3986 ``scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )``."""
    if not scheme or not scheme[0].isalpha():
        return False
    return all(c.isalnum() or c in "+-." for c in scheme)


def parse_locator_entry(
    cursor: Cursor, max_uri_bytes: int = DEFAULT_LOCATOR_MAX_URI_BYTES
) -> LocatorEntry:
    """Parse a single locator entry from the cursor's position."""
    raw_length = cursor.read_u32_le()
    if raw_length < MIN_LOCATOR_URI_BYTES:
        raise CorruptError(
            f"locator length {raw_length} is below minimum {MIN_LOCATOR_URI_BYTES}"
        )
    if raw_length > max_uri_bytes:
        raise CorruptError(
            f"locator length {raw_length} exceeds ceiling {max_uri_bytes}"
        )
    uri_bytes = cursor.read(raw_length)
    try:
        uri = uri_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise CorruptError(
            f"locator URI is not valid UTF-8 ({raw_length} bytes)"
        ) from e
    if ":" not in uri:
        raise CorruptError(f"locator URI {uri!r} missing scheme separator ':'")
    scheme, rest = uri.split(":", 1)
    if not scheme:
        raise CorruptError(f"locator URI {uri!r} has empty scheme")
    if not _is_valid_scheme(scheme):
        raise CorruptError(
            f"locator URI {uri!r} scheme {scheme!r} does not match RFC 3986 grammar"
        )
    if not rest:
        raise CorruptError(f"locator URI {uri!r} has empty scheme-specific part")
    return LocatorEntry(uri=uri)


def parse_locator_entries(
    cursor: Cursor,
    count: int,
    max_uri_bytes: int = DEFAULT_LOCATOR_MAX_URI_BYTES,
) -> list[LocatorEntry]:
    """Parse ``count`` consecutive locator entries.

    Performs the pre-allocation DoS check: the cursor's remaining
    bytes must be at least ``count * (4 + MIN_LOCATOR_URI_BYTES)``
    BEFORE the loop starts.
    """
    min_entry_width = LOCATOR_LENGTH_PREFIX_LEN + MIN_LOCATOR_URI_BYTES
    min_total = count * min_entry_width
    if cursor.remaining_len < min_total:
        raise TruncatedError(have=cursor.remaining_len, need=min_total)
    entries: list[LocatorEntry] = []
    for index in range(count):
        try:
            entry = parse_locator_entry(cursor, max_uri_bytes=max_uri_bytes)
        except (CorruptError, UnsupportedFeatureError) as e:
            # Annotate with the entry index for easier debugging.
            raise CorruptError(f"locator entry {index}: {e}") from e
        entries.append(entry)
    return entries


__all__ = [
    "DEFAULT_LOCATOR_MAX_URI_BYTES",
    "LOCATOR_LENGTH_PREFIX_LEN",
    "MIN_LOCATOR_URI_BYTES",
    "LocatorEntry",
    "parse_locator_entries",
    "parse_locator_entry",
]

