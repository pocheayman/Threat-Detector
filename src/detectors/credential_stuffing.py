"""
Credential-stuffing / password-spraying detector.   MITRE ATT&CK T1110.004

Signal: ONE IP failing against MANY DIFFERENT usernames, a few tries each
(attackers replay leaked username/password pairs or spray common passwords).
It never trips the brute-force rule because no single account sees many
failures - which is exactly why it needs its own detector.

Algorithm: per IP, slide a window over failures while keeping a hash map of
username -> count; fire when the map holds >= N distinct usernames.
"""

from __future__ import annotations

import pandas as pd

from .base import (Alert, DetectorConfig, count_between, find_breach, is_trusted, merge_windows,
                   to_datetime, with_seconds)

MITRE_ID = "T1110.004"
MITRE_NAME = "Brute Force: Credential Stuffing"


def _windows(times, users, window: float, min_distinct: int):
    hits = []
    counts: dict[str, int] = {}
    i = 0
    for j in range(len(times)):
        counts[users[j]] = counts.get(users[j], 0) + 1
        while times[j] - times[i] > window:
            u = users[i]
            counts[u] -= 1
            if counts[u] == 0:
                del counts[u]
            i += 1
        if len(counts) >= min_distinct:
            hits.append((times[i], times[j]))
    return hits


def detect(df: pd.DataFrame, cfg: DetectorConfig = DetectorConfig()) -> list[Alert]:
    df = with_seconds(df)
    fails = df[df["failed"]].sort_values("t")
    successes = df[~df["failed"]]
    alerts: list[Alert] = []

    for ip, g in fails.groupby("ip", sort=False):
        if is_trusted(str(ip), cfg.trusted_networks):
            continue            # shared office address: many users failing is expected
        times = g["t"].to_numpy()
        users = g["user"].tolist()
        hits = _windows(times, users, cfg.stuff_window_s, cfg.stuff_distinct_users)
        for start, end in merge_windows(hits):
            in_window = g[(g["t"] >= start) & (g["t"] <= end)]
            targeted = tuple(sorted(in_window["user"].unique()))
            attempts = count_between(times, start, end)
            breached_user = find_breach(successes, ip, start, end, cfg.breach_grace_s)
            breached = breached_user is not None
            alerts.append(Alert(
                type="credential_stuffing",
                severity="critical" if breached else "high",
                mitre_id=MITRE_ID,
                mitre_name=MITRE_NAME,
                ip=str(ip),
                users=targeted,
                start=to_datetime(start),
                end=to_datetime(end),
                count=attempts,
                description=(
                    f"{attempts} failed logins across {len(targeted)} different usernames from {ip}"
                    + (f" - '{breached_user}' then logged in successfully" if breached else "")
                ),
                breached=breached,
            ))
    return alerts
