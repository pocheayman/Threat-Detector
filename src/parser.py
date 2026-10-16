"""
Log parser: turns raw auth.log lines into structured events.

Line format (produced by generator.py):
  2026-10-12T09:15:32Z auth user=alice ip=49.37.12.8 result=SUCCESS city=Bengaluru lat=12.97 lon=77.59

Design notes (good interview talking points):
  * parse_line() never raises on bad input - it returns None. One corrupt
    line must not crash ingestion of a million good ones.
  * parse_file() streams line by line, so memory stays flat on huge logs,
    and counts how many lines were rejected.
  * Values are validated (IP address, result enum, lat/lon ranges), not
    just split - detectors downstream can trust the data.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

import pandas as pd

VALID_RESULTS = {"SUCCESS", "FAIL"}

# <timestamp> <source> key=value key=value ...
_LINE_RE = re.compile(r"^(?P<ts>\S+)\s+(?P<source>\S+)\s+(?P<rest>.+)$")


@dataclass(frozen=True)
class AuthEvent:
    ts: datetime          # timezone-aware, UTC
    user: str
    ip: str
    result: str           # "SUCCESS" or "FAIL"
    city: str
    lat: float
    lon: float

    @property
    def failed(self) -> bool:
        return self.result == "FAIL"


@dataclass
class ParseStats:
    total: int = 0
    parsed: int = 0
    rejected: int = 0

    @property
    def reject_rate(self) -> float:
        return self.rejected / self.total if self.total else 0.0


def _parse_fields(rest: str) -> Optional[dict]:
    """Split 'a=1 b=2 city=New York lat=...' into a dict.

    City names can contain spaces ('New York'), so we split on the *next*
    key= token rather than on whitespace.
    """
    matches = list(re.finditer(r"(\w+)=", rest))
    if not matches:
        return None
    fields = {}
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(rest)
        key = m.group(1)
        if key in fields:
            # A repeated key means a value contained something like "result=SUCCESS":
            # an attempt to forge fields (log injection). Reject the whole line.
            return None
        fields[key] = rest[m.end():end].strip()
    return fields


def parse_line(line: str) -> Optional[AuthEvent]:
    """Parse one log line. Returns None if the line is malformed."""
    line = line.strip()
    if not line:
        return None

    m = _LINE_RE.match(line)
    if not m or m.group("source") != "auth":
        return None

    try:
        ts = datetime.strptime(m.group("ts"), "%Y-%m-%dT%H:%M:%SZ")
        ts = ts.replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    fields = _parse_fields(m.group("rest"))
    if not fields:
        return None

    required = ("user", "ip", "result", "city", "lat", "lon")
    if any(k not in fields or fields[k] == "" for k in required):
        return None

    try:
        ipaddress.ip_address(fields["ip"])
        lat = float(fields["lat"])
        lon = float(fields["lon"])
    except ValueError:
        return None

    result = fields["result"].upper()
    if result not in VALID_RESULTS:
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None

    return AuthEvent(
        ts=ts, user=fields["user"], ip=fields["ip"], result=result,
        city=fields["city"], lat=lat, lon=lon,
    )


def parse_lines(lines: Iterable[str], stats: Optional[ParseStats] = None) -> Iterator[AuthEvent]:
    """Parse any iterable of lines (a file object, a list, text.splitlines()).

    Shared by the file reader and the HTTP upload endpoint so both behave identically.
    """
    stats = stats if stats is not None else ParseStats()
    for line in lines:
        if not line.strip():
            continue
        stats.total += 1
        event = parse_line(line)
        if event is None:
            stats.rejected += 1
            continue
        stats.parsed += 1
        yield event


def iter_events(path: str | Path, stats: Optional[ParseStats] = None) -> Iterator[AuthEvent]:
    """Stream events from a log file one at a time (constant memory)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        yield from parse_lines(f, stats)


def parse_file(path: str | Path) -> tuple[list[AuthEvent], ParseStats]:
    """Parse a whole file. Returns (events, stats)."""
    stats = ParseStats()
    events = list(iter_events(path, stats))
    return events, stats


def to_dataframe(events: list[AuthEvent]) -> pd.DataFrame:
    """Events -> DataFrame sorted by time, with proper dtypes.

    Detectors and the ML step (Step 5) work on this.
    """
    columns = ["ts", "user", "ip", "result", "city", "lat", "lon"]
    if not events:
        empty = pd.DataFrame(columns=columns)
        empty["ts"] = pd.to_datetime(empty["ts"], utc=True)   # keep dtypes right for detectors
        empty["failed"] = pd.Series(dtype=bool)
        return empty
    df = pd.DataFrame([asdict(e) for e in events], columns=columns)
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    df["failed"] = df["result"] == "FAIL"
    return df.sort_values("ts").reset_index(drop=True)


if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "data/auth.log"
    events, stats = parse_file(path)
    df = to_dataframe(events)
    print(f"Parsed {stats.parsed}/{stats.total} lines "
          f"({stats.rejected} rejected, {stats.reject_rate:.2%})")
    print(df.head())
    print(f"\nFailure rate: {df['failed'].mean():.2%}")
    print(f"Unique users: {df['user'].nunique()}  Unique IPs: {df['ip'].nunique()}")
