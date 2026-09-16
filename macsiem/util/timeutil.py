"""Time normalization.

Everything inside MacSIEM is a UTC-aware ``datetime`` or an ISO-8601 string with
microsecond precision.  macOS hands us at least five different time formats
(Endpoint Security nanosecond epochs, unified-log local strings with offsets,
``ps`` elapsed times, plist dates, BSD ``last`` output), and a timeline that
silently mixes them is worse than no timeline at all.
"""

from __future__ import annotations

import datetime as _dt
import re

UTC = _dt.timezone.utc

ISO_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"

# 2023-06-06 11:02:33.123456-0700  (unified log --style default / ndjson)
_UNIFIED_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?"
    r"\s*(Z|[+-]\d{2}:?\d{2})?$"
)


def now() -> _dt.datetime:
    """Current time, UTC-aware.  The only clock source in the codebase."""
    return _dt.datetime.now(UTC)


def now_iso() -> str:
    return to_iso(now())


def to_iso(value: _dt.datetime) -> str:
    """Render a datetime as a stable, sortable, UTC ISO-8601 string."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def from_epoch(seconds: float) -> _dt.datetime:
    return _dt.datetime.fromtimestamp(float(seconds), UTC)


def from_nanos(nanos: int) -> _dt.datetime:
    """Endpoint Security timestamps arrive as nanoseconds since the epoch."""
    return _dt.datetime.fromtimestamp(int(nanos) / 1_000_000_000, UTC)


def parse(value, default=None):
    """Best-effort parse of any timestamp macOS might hand us.

    Returns ``default`` rather than raising: a malformed timestamp on one event
    must never take down a sensor.
    """
    if value is None or value == "":
        return default
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        # Heuristic: ES nanoseconds are ~1e18, milliseconds ~1e12, seconds ~1e9.
        number = float(value)
        if number > 1e17:
            return from_nanos(int(number))
        if number > 1e11:
            return from_epoch(number / 1000.0)
        return from_epoch(number)

    text = str(value).strip()
    if text.isdigit():
        return parse(int(text), default)

    match = _UNIFIED_RE.match(text)
    if match:
        year, month, day, hour, minute, second, frac, offset = match.groups()
        micro = int((frac or "0").ljust(6, "0")[:6])
        naive = _dt.datetime(
            int(year), int(month), int(day), int(hour), int(minute), int(second), micro
        )
        if offset in (None, "", "Z"):
            return naive.replace(tzinfo=UTC)
        sign = 1 if offset[0] == "+" else -1
        digits = offset[1:].replace(":", "")
        delta = _dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
        return (naive - sign * delta).replace(tzinfo=UTC)

    try:  # ISO-8601, including the trailing-Z spelling Python 3.9 dislikes.
        return _dt.datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return default


def parse_duration(text, default=None):
    """Parse ``30m``/``2h``/``45s``/``7d`` into a timedelta (for --window flags)."""
    if text is None:
        return default
    if isinstance(text, _dt.timedelta):
        return text
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*", str(text), re.I)
    if not match:
        return default
    amount = float(match.group(1))
    unit = (match.group(2) or "s").lower()
    factor = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
    return _dt.timedelta(seconds=amount * factor)


def window(center: _dt.datetime, before, after=None):
    """Return ``(start, end)`` around an event, for log slicing."""
    before_delta = parse_duration(before, _dt.timedelta(minutes=30))
    after_delta = parse_duration(after, before_delta) if after is not None else before_delta
    return center - before_delta, center + after_delta
