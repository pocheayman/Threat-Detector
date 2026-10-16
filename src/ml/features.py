"""
Feature engineering for the anomaly detector.

Unit of analysis: one source IP during one clock hour. Why this unit:
  * attacks are about *a source behaving unusually*, so per-IP is the natural entity
  * an hour is long enough to see low-and-slow attacks that stay under a
    "N failures in 5 minutes" rule, but short enough to localise the alert

Per (ip, hour) we compute:
  events               all login attempts
  fails / successes    outcome counts
  fail_ratio           share of attempts that failed
  distinct_users       accounts touched
  distinct_fail_users  accounts that saw a failure
  max_fails_5min       burstiness: most failures inside any 5-minute window
  mean_gap_s           average seconds between attempts
  gap_regularity       how clockwork-like the timing is (machines are regular, people are not)
  distinct_cities      geo spread of the attempts
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from ..detectors.base import with_seconds

FEATURES = [
    "events", "fails", "successes", "fail_ratio", "distinct_users",
    "distinct_fail_users", "max_fails_5min", "mean_gap_s", "distinct_cities",
]

# Computed for every row but NOT used by default: on development data it made no measurable
# difference (the nine features above already separate the attacks), so the simpler model wins.
# Pass feature_names=FEATURES + EXTRA_FEATURES to train_model to include it.
EXTRA_FEATURES = ["gap_regularity"]
ALL_FEATURES = FEATURES + EXTRA_FEATURES

BURST_WINDOW_S = 300.0


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return one row per (ip, hour) with FEATURES plus bookkeeping columns
    (ip, hour, start_t, end_t, fail_users) used to turn flagged rows into alerts."""
    columns = ["ip", "hour", "start_t", "end_t", "fail_users", *ALL_FEATURES]
    if df.empty:
        return pd.DataFrame(columns=columns)

    df = with_seconds(df)
    df = df.assign(hour=(df["t"] // 3600).astype(int))
    rows = []
    for (ip, hour), g in df.groupby(["ip", "hour"], sort=False):
        t = np.sort(g["t"].to_numpy())
        failed = g[g["failed"]]
        ft = np.sort(failed["t"].to_numpy())
        n, nf = len(g), len(failed)

        max5 = 0
        if nf:
            # for each failure, how many failures fall in [t, t + 5 min]
            max5 = int((np.searchsorted(ft, ft + BURST_WINDOW_S, side="right") - np.arange(nf)).max())
        gaps = np.diff(t)
        # Scripts fire at near-constant intervals; people do not. 1/(1+CV) is ~1 for clockwork,
        # ~0.5 for random human timing. Hours with too few attempts get the neutral 0.5.
        if len(gaps) >= 3 and gaps.mean() > 0:
            regularity = float(1.0 / (1.0 + gaps.std() / gaps.mean()))
        else:
            regularity = 0.5
        rows.append({
            "ip": ip,
            "hour": int(hour),
            "start_t": float(t[0]),
            "end_t": float(t[-1]),
            "fail_users": tuple(sorted(failed["user"].unique())),
            "events": n,
            "fails": nf,
            "successes": n - nf,
            "fail_ratio": nf / n,
            "distinct_users": g["user"].nunique(),
            "distinct_fail_users": failed["user"].nunique(),
            "max_fails_5min": max5,
            "mean_gap_s": float(gaps.mean()) if len(gaps) else 3600.0,
            "gap_regularity": regularity,
            "distinct_cities": g["city"].nunique(),
        })
    return pd.DataFrame(rows, columns=columns)
