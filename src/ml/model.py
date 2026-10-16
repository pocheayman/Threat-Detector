"""
Isolation Forest anomaly detector for authentication behaviour.

How it works (interview version):
  Isolation Forest builds many random trees that split the data on random features.
  Unusual points sit alone in sparse regions, so they are isolated after only a few
  splits; typical points need many. The average path length becomes the anomaly score.
  It is unsupervised: no attack labels are needed to train it.

Setup used here ("novelty detection"):
  1. fit on a clean historical period (normal traffic only, which may include known
     benign oddities such as a shared office IP)
  2. set the alert threshold at a high percentile of the TRAINING scores
  3. score new data; rows above the threshold AND with at least `min_fails` failures
     become alerts

The `min_fails` floor is a deliberate domain guard: an hour with two failed logins is never
worth an analyst's time, however statistically unusual it looks.

Every alert carries a plain-language reason built from robust z-scores against the
training data, because "the model said so" is not an acceptable explanation to an analyst.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ..detectors.base import Alert, DetectorConfig, find_breach, is_trusted, to_datetime, with_seconds
from .features import FEATURES, build_features

MITRE_ID = "T1110"
MITRE_NAME = "Brute Force"
ALERT_TYPE = "anomalous_activity"

REASONS = {
    "fails": "{v:.0f} failed logins in the hour (typical {m:.0f})",
    "events": "{v:.0f} login attempts in the hour (typical {m:.0f})",
    "distinct_fail_users": "{v:.0f} different accounts failing (typical {m:.0f})",
    "max_fails_5min": "{v:.0f} failures inside 5 minutes (typical {m:.0f})",
    "fail_ratio": "{v:.0%} of attempts failed (typical {m:.0%})",
    "distinct_users": "{v:.0f} accounts touched (typical {m:.0f})",
    "mean_gap_s": "attempts only {v:.0f}s apart on average (typical {m:.0f}s)",
    "gap_regularity": "attempts arrive at near-constant intervals (regularity {v:.2f}, typical {m:.2f})",
    "distinct_cities": "attempts geolocated to {v:.0f} cities (typical {m:.0f})",
    "successes": "{v:.0f} successful logins (typical {m:.0f})",
}


@dataclass
class AnomalyModel:
    forest: IsolationForest
    threshold: float                       # anomaly score at/above which a row is flagged
    medians: dict[str, float]
    scales: dict[str, float]               # robust spread (1.4826 * MAD, floored) per feature
    quantile: float = 0.999
    min_fails: int = 8
    merge_gap_hours: int = 1               # flagged hours this close become one alert
    train_rows: int = 0
    feature_names: list[str] = field(default_factory=lambda: list(FEATURES))
    meta: dict = field(default_factory=dict)

    # ---- scoring ----
    def scores(self, feats: pd.DataFrame) -> np.ndarray:
        """Higher = more anomalous."""
        if feats.empty:
            return np.array([])
        return -self.forest.score_samples(feats[self.feature_names].to_numpy(dtype=float))

    def flag(self, feats: pd.DataFrame) -> pd.DataFrame:
        """Feature rows that should raise an alert, with their score."""
        if feats.empty:
            return feats.assign(score=[])
        out = feats.assign(score=self.scores(feats))
        return out[(out["score"] >= self.threshold) & (out["fails"] >= self.min_fails)]

    # ---- explanations ----
    def explain(self, row: pd.Series, top: int = 2) -> list[str]:
        z = {f: (row[f] - self.medians[f]) / self.scales[f] for f in self.feature_names}
        worst = [f for f, v in sorted(z.items(), key=lambda kv: kv[1], reverse=True) if v > 0][:top]
        return [REASONS[f].format(v=row[f], m=self.medians[f]) for f in worst]

    # ---- alerts ----
    def detect(self, df: pd.DataFrame, cfg: DetectorConfig = DetectorConfig()) -> list[Alert]:
        df = with_seconds(df)
        flagged = self.flag(build_features(df))
        if cfg.trusted_networks and not flagged.empty:
            flagged = flagged[~flagged["ip"].map(lambda ip: is_trusted(str(ip), cfg.trusted_networks))]
        if flagged.empty:
            return []
        successes = df[~df["failed"]]
        alerts: list[Alert] = []

        for ip, g in flagged.sort_values("hour").groupby("ip", sort=False):
            episode: list[pd.Series] = []
            for _, row in g.iterrows():
                if episode and row["hour"] - episode[-1]["hour"] > self.merge_gap_hours:
                    alerts.append(self._alert(ip, episode, successes, cfg))
                    episode = []
                episode.append(row)
            if episode:
                alerts.append(self._alert(ip, episode, successes, cfg))
        return sorted(alerts, key=lambda a: a.start)

    def _alert(self, ip: str, rows: list[pd.Series], successes: pd.DataFrame, cfg: DetectorConfig) -> Alert:
        start = min(r["start_t"] for r in rows)
        end = max(r["end_t"] for r in rows)
        fails = int(sum(r["fails"] for r in rows))
        users = tuple(sorted({u for r in rows for u in r["fail_users"]}))
        worst = max(rows, key=lambda r: r["score"])
        reasons = "; ".join(self.explain(worst)) or "unusual combination of login behaviour"
        breached_by = find_breach(successes, str(ip), start, end, cfg.breach_grace_s)
        text = f"Unusual login activity from {ip}: {reasons}"
        if breached_by:
            text += f" - '{breached_by}' then logged in successfully"
        return Alert(
            type=ALERT_TYPE,
            severity="critical" if breached_by else "high",
            mitre_id=MITRE_ID,
            mitre_name=MITRE_NAME,
            ip=str(ip),
            users=users[:50],
            start=to_datetime(start),
            end=to_datetime(end),
            count=fails,
            description=text,
            breached=bool(breached_by),
        )

    # ---- persistence ----
    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: str | Path) -> "AnomalyModel":
        model = joblib.load(path)
        if not isinstance(model, AnomalyModel):
            raise ValueError(f"{path} does not contain an AnomalyModel")
        return model


def train_model(df: pd.DataFrame, quantile: float = 0.999, min_fails: int = 8,
                n_estimators: int = 200, seed: int = 0,
                feature_names: list[str] | None = None,
                trusted_networks: tuple[str, ...] = ()) -> AnomalyModel:
    """Fit on clean history and calibrate the alert threshold on the training scores.

    The threshold sits at `quantile` of the training scores (0.999 = only the most extreme
    0.1% of normal hours would have alerted). Rows from trusted networks are left out of
    training: those ranges are handled by the allowlist, and letting their login storms into
    the training data would push the threshold above real attacks."""
    names = list(feature_names or FEATURES)
    feats = build_features(with_seconds(df))
    if trusted_networks:
        feats = feats[~feats["ip"].map(lambda ip: is_trusted(str(ip), trusted_networks))]
    if len(feats) < 20:
        raise ValueError("Need at least 20 (ip, hour) rows of history to train; got %d" % len(feats))
    X = feats[names].to_numpy(dtype=float)

    forest = IsolationForest(n_estimators=n_estimators, contamination="auto", random_state=seed, n_jobs=1)
    forest.fit(X)
    train_scores = -forest.score_samples(X)

    medians, scales = {}, {}
    for f in names:
        col = feats[f].to_numpy(dtype=float)
        med = float(np.median(col))
        mad = float(np.median(np.abs(col - med))) * 1.4826
        medians[f] = med
        scales[f] = max(mad, 0.1 if f in ("fail_ratio", "gap_regularity") else 1.0)   # floor: counts rarely vary by <1

    return AnomalyModel(
        forest=forest,
        threshold=float(np.quantile(train_scores, quantile)),
        medians=medians, scales=scales,
        quantile=quantile, min_fails=min_fails, train_rows=len(feats),
        feature_names=names,
    )
