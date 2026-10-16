"""
Shared building blocks for all detectors.

  * Alert           - what every detector emits
  * DetectorConfig  - all thresholds in one place (tune them, then re-score)
  * sliding_windows - the core DSA idea: two pointers over sorted timestamps
  * merge_windows   - collapse overlapping hits into one alert per attack
  * haversine_km    - great-circle distance between two lat/lon points
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from typing import Sequence

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class DetectorConfig:
    # Brute force: >= N failures for the SAME (ip, user) inside the window
    bf_threshold: int = 10
    bf_window_s: float = 300.0
    # Credential stuffing: >= N DISTINCT usernames failing from one IP in window
    stuff_distinct_users: int = 10
    stuff_window_s: float = 600.0
    # Impossible travel: implied speed above this between two logins
    travel_max_kmh: float = 900.0      # roughly a commercial airliner
    travel_min_km: float = 100.0       # ignore tiny moves / GeoIP noise
    travel_merge_s: float = 1800.0     # hops by one user closer than this become ONE alert
    # A successful login this soon after an attack counts as a breach
    breach_grace_s: float = 60.0
    # Source ranges the organisation owns (office egress, VPN gateway), as CIDR strings.
    # Many people sharing one address looks like credential stuffing, so the stuffing and ML
    # detectors ignore these ranges. Brute force on a single account still alerts.
    trusted_networks: tuple[str, ...] = ()


@dataclass(frozen=True)
class Alert:
    type: str                 # brute_force | credential_stuffing | impossible_travel
    severity: str             # high | critical
    mitre_id: str
    mitre_name: str
    ip: str
    users: tuple[str, ...]
    start: datetime
    end: datetime
    count: int                # failed attempts (or 2 logins for travel)
    description: str
    breached: bool = False

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "mitre_id": self.mitre_id,
            "mitre_name": self.mitre_name,
            "ip": self.ip,
            "users": list(self.users),
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "count": self.count,
            "description": self.description,
            "breached": self.breached,
        }


@lru_cache(maxsize=256)
def _network(cidr: str):
    return ipaddress.ip_network(cidr, strict=False)


def is_trusted(ip: str, networks: Sequence[str]) -> bool:
    """True if `ip` falls inside any trusted CIDR range."""
    if not networks:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in _network(n) for n in networks)


def with_seconds(df: pd.DataFrame) -> pd.DataFrame:
    """Add a float 't' column (epoch seconds) so window maths is plain numpy."""
    if "t" in df.columns:
        return df
    epoch = pd.Timestamp("1970-01-01", tz="UTC")
    return df.assign(t=(df["ts"] - epoch).dt.total_seconds())


def sliding_windows(times: Sequence[float], window: float, min_count: int) -> list[tuple[float, float]]:
    """For sorted `times`, return (start, end) of every window of length <= `window`
    that holds at least `min_count` events. O(n) - each pointer only moves forward.
    """
    hits = []
    i = 0
    for j in range(len(times)):
        while times[j] - times[i] > window:
            i += 1
        if j - i + 1 >= min_count:
            hits.append((times[i], times[j]))
    return hits


def merge_windows(windows: list[tuple[float, float]]) -> list[tuple[float, float]]:
    """Merge overlapping windows so one attack produces one alert, not hundreds."""
    merged: list[list[float]] = []
    for start, end in sorted(windows):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


def count_between(times: np.ndarray, start: float, end: float) -> int:
    """How many sorted timestamps fall in [start, end]."""
    return int(np.searchsorted(times, end, side="right") - np.searchsorted(times, start, side="left"))


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0088  # mean Earth radius, km
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = p2 - p1
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def to_datetime(t: float) -> datetime:
    return pd.Timestamp(t, unit="s", tz="UTC").to_pydatetime()


def find_breach(successes: pd.DataFrame, ip: str, start: float, end: float,
                grace: float, user: str | None = None) -> str | None:
    """Return the username of a successful login from `ip` during or just after
    an attack (optionally restricted to one user), else None."""
    s = successes[successes["ip"] == ip]
    if user is not None:
        s = s[s["user"] == user]
    hit = s[(s["t"] >= start) & (s["t"] <= end + grace)]
    return None if hit.empty else str(hit.iloc[0]["user"])
