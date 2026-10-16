"""
Brute-force detector.   MITRE ATT&CK T1110.001 - Password Guessing

Signal: many failed logins for the SAME account from the SAME IP in a short window.
Normal users mistype a password once or twice; a script hammering one account
produces dozens of failures within seconds.

Algorithm: group failures by (ip, user), run a two-pointer sliding window over
the timestamps, merge overlapping hits into one alert per episode.
"""

from __future__ import annotations

import pandas as pd

from .base import (Alert, DetectorConfig, count_between, find_breach, merge_windows,
                   sliding_windows, to_datetime, with_seconds)

MITRE_ID = "T1110.001"
MITRE_NAME = "Brute Force: Password Guessing"


def detect(df: pd.DataFrame, cfg: DetectorConfig = DetectorConfig()) -> list[Alert]:
    df = with_seconds(df)
    fails = df[df["failed"]].sort_values("t")
    successes = df[~df["failed"]]
    alerts: list[Alert] = []

    for (ip, user), g in fails.groupby(["ip", "user"], sort=False):
        times = g["t"].to_numpy()
        hits = sliding_windows(times, cfg.bf_window_s, cfg.bf_threshold)
        for start, end in merge_windows(hits):
            attempts = count_between(times, start, end)
            breached_user = find_breach(successes, ip, start, end, cfg.breach_grace_s, user=user)
            breached = breached_user is not None
            alerts.append(Alert(
                type="brute_force",
                severity="critical" if breached else "high",
                mitre_id=MITRE_ID,
                mitre_name=MITRE_NAME,
                ip=str(ip),
                users=(str(user),),
                start=to_datetime(start),
                end=to_datetime(end),
                count=attempts,
                description=(
                    f"{attempts} failed logins for '{user}' from {ip} in {end - start:.0f}s"
                    + (" - followed by a SUCCESSFUL login (possible account takeover)" if breached else "")
                ),
                breached=breached,
            ))
    return alerts
