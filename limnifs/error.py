"""Exception hierarchy for parse-time errors.

All errors surface as :class:`ParseError` (or a subclass). The
hierarchy mirrors the Rust ``CoreError`` variants so differential
testing can compare error kinds across implementations.
"""

from __future__ import annotations


class ParseError(Exception):
    """Base class for all LimniFS parse errors."""


class TruncatedError(ParseError):
    """Fewer than the required bytes available."""

    def __init__(self, have: int, need: int) -> None:
        super().__init__(f"truncated input: have {have} bytes, need {need}")
        self.have = have
        self.need = need


class BadMagicError(ParseError):
    """Magic bytes did not match the expected constant."""

    def __init__(self, found: bytes, expected: bytes) -> None:
        super().__init__(
            f"bad magic: expected {expected!r}, found {found!r}"
        )
        self.found = found
        self.expected = expected


class CorruptError(ParseError):
    """A structural invariant was violated."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"corrupt: {reason}")
        self.reason = reason


class UnsupportedFeatureError(ParseError):
    """The image uses a feature the reader does not implement."""

    def __init__(self, feature: str) -> None:
        super().__init__(f"unsupported feature: {feature}")
        self.feature = feature
