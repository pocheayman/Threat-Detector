"""Hybrid detection: rules first, ML only for what the rules did not already flag."""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

import pandas as pd

from .detectors import DetectorConfig, run_all
from .detectors.base import Alert
from .ml import AnomalyModel


def merge_hybrid(rule_alerts: list[Alert], ml_alerts: list[Alert], slack_s: float = 600.0) -> list[Alert]:
    """Keep every rule alert; keep an ML alert only if no rule alert for the same IP
    overlaps it. The ML layer is there to fill the rules' blind spots, not repeat them."""
    slack = timedelta(seconds=slack_s)
    kept = []
    for m in ml_alerts:
        covered = any(r.ip == m.ip and r.type != "impossible_travel"
                      and not (r.end + slack < m.start or r.start - slack > m.end) for r in rule_alerts)
        if not covered:
            kept.append(m)
    return sorted(rule_alerts + kept, key=lambda a: a.start)


def detect(df: pd.DataFrame, cfg: DetectorConfig = DetectorConfig(),
           model: Optional[AnomalyModel] = None) -> list[Alert]:
    rules = run_all(df, cfg)
    if model is None:
        return rules
    return merge_hybrid(rules, model.detect(df, cfg))
