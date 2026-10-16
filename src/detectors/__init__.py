"""Detector package: run_all() applies every detector to a parsed DataFrame."""

from __future__ import annotations

import pandas as pd

from . import brute_force, credential_stuffing, impossible_travel
from .base import Alert, DetectorConfig, with_seconds

DETECTORS = (brute_force, credential_stuffing, impossible_travel)


def run_all(df: pd.DataFrame, cfg: DetectorConfig = DetectorConfig()) -> list[Alert]:
    df = with_seconds(df)          # compute the numeric time column once
    alerts: list[Alert] = []
    for module in DETECTORS:
        alerts.extend(module.detect(df, cfg))
    return sorted(alerts, key=lambda a: a.start)


__all__ = ["Alert", "DetectorConfig", "run_all", "DETECTORS"]
