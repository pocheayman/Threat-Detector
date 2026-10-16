"""
Ingest: raw log text -> parse -> detect -> store.

Used by the API (upload button / POST /api/ingest) and by the command line:

    python -m src.ingest data/auth.log
    python -m src.ingest data/auth.log --db data/threat.db --append
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import time
from pathlib import Path

from . import db
from .detectors import Alert, DetectorConfig
from .ml import AnomalyModel
from .parser import ParseStats, parse_lines, to_dataframe
from .pipeline import detect

DEFAULT_MODEL_PATH = "models/iforest.joblib"


def load_runtime(model_path: str | None = None, trusted: str | None = None):
    """Detector config + optional ML model from arguments or the environment.

    THREAT_MODEL            path to a saved Isolation Forest (default models/iforest.joblib if it exists)
    THREAT_TRUSTED_NETWORKS comma-separated CIDRs of known-benign ranges, e.g. the office"""
    trusted = os.environ.get("THREAT_TRUSTED_NETWORKS", "") if trusted is None else trusted
    cfg = DetectorConfig(trusted_networks=tuple(n.strip() for n in trusted.split(",") if n.strip()))
    path = model_path or os.environ.get("THREAT_MODEL") or DEFAULT_MODEL_PATH
    model = AnomalyModel.load(path) if Path(path).exists() else None
    return cfg, model


def analyze_text(text: str, cfg: DetectorConfig = DetectorConfig(),
                 model: AnomalyModel | None = None) -> tuple[ParseStats, list[Alert], float]:
    """Parse log text and run every detector (plus the ML layer when a model is given). Returns (parse stats, alerts, seconds)."""
    t0 = time.perf_counter()
    stats = ParseStats()
    events = list(parse_lines(text.splitlines(), stats))
    alerts = detect(to_dataframe(events), cfg, model)
    return stats, alerts, time.perf_counter() - t0


def ingest_text(conn: sqlite3.Connection, text: str, replace: bool = True,
                cfg: DetectorConfig | None = None, model: AnomalyModel | None = None) -> dict:
    stats, alerts, seconds = analyze_text(text, cfg or DetectorConfig(), model)
    stored = db.insert_alerts(conn, alerts, replace=replace)
    db.record_ingest(conn, stats.total, stats.parsed, stats.rejected, stored, seconds)
    return {
        "lines": stats.total,
        "parsed": stats.parsed,
        "rejected": stats.rejected,
        "alerts": stored,
        "seconds": round(seconds, 3),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Load an auth log into the alert database")
    ap.add_argument("log", help="path to the log file")
    ap.add_argument("--db", default="data/threat.db")
    ap.add_argument("--append", action="store_true", help="keep existing alerts instead of replacing them")
    ap.add_argument("--model", default=None, help="Isolation Forest model (default models/iforest.joblib if present)")
    ap.add_argument("--trusted", default=None, help="comma-separated benign CIDR ranges")
    ap.add_argument("--no-ml", action="store_true", help="rules only")
    args = ap.parse_args()
    cfg, model = load_runtime(args.model, args.trusted)
    if args.no_ml:
        model = None

    db.init_db(args.db)
    conn = db.connect(args.db)
    try:
        text = Path(args.log).read_text(encoding="utf-8", errors="replace")
        result = ingest_text(conn, text, replace=not args.append, cfg=cfg, model=model)
    finally:
        conn.close()
    print(f"Ingested {result['parsed']}/{result['lines']} lines "
          f"({result['rejected']} rejected) -> {result['alerts']} alerts in {result['seconds']}s")
    print(f"Detection: rules{' + Isolation Forest' if model else ' only'}; Database: {args.db}")


if __name__ == "__main__":
    main()
