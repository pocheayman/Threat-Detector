"""
End-to-end pipeline:  parse log -> run detectors -> print alerts -> score vs truth.

    python -m src.main                         # uses data/auth.log
    python -m src.main --log other.log --no-score
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .detectors import DetectorConfig
from .evaluate import evaluate, format_report, load_json, load_truth
from .ml import AnomalyModel
from .pipeline import detect
from .parser import parse_file, to_dataframe


def main() -> None:
    ap = argparse.ArgumentParser(description="Run threat detectors on an auth log")
    ap.add_argument("--log", default="data/auth.log")
    ap.add_argument("--truth", default="data/ground_truth.json")
    ap.add_argument("--out", default="data/alerts.json")
    ap.add_argument("--model", default=None, help="saved Isolation Forest model; adds the ML layer (hybrid)")
    ap.add_argument("--trusted", default="", help="comma-separated CIDR ranges known to be benign (e.g. office)")
    ap.add_argument("--no-score", action="store_true", help="skip scoring against ground truth")
    args = ap.parse_args()

    t0 = time.perf_counter()
    events, stats = parse_file(args.log)
    df = to_dataframe(events)
    t_parse = time.perf_counter() - t0

    t1 = time.perf_counter()
    trusted = tuple(n.strip() for n in args.trusted.split(",") if n.strip())
    model = AnomalyModel.load(args.model) if args.model else None
    alerts = detect(df, DetectorConfig(trusted_networks=trusted), model)
    t_detect = time.perf_counter() - t1

    print(f"Parsed {stats.parsed}/{stats.total} lines in {t_parse:.2f}s; "
          f"detectors ran in {t_detect:.2f}s "
          f"({stats.parsed / max(t_parse + t_detect, 1e-9):,.0f} events/s end to end)\n")

    print(f"{len(alerts)} alerts")
    for a in alerts:
        print(f"  [{a.severity.upper():<8}] {a.start:%Y-%m-%d %H:%M:%S}  {a.mitre_id:<10} {a.description}")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps([a.to_dict() for a in alerts], indent=2))
    print(f"\nSaved alerts to {args.out}")

    if not args.no_score and Path(args.truth).exists():
        report = evaluate(alerts, load_truth(args.truth),
                          benign=load_json(Path(args.truth).with_name("benign_scenarios.json")))
        print("\n=== Detection quality vs ground truth ===")
        print(format_report(report, stats.parsed))
        if report["missed"]:
            print("\nMissed attacks:")
            for m in report["missed"]:
                print(f"  {m['type']} ip={m['ip']} {m['start']}")
        if report["false_positives"]:
            print("\nFalse positives:")
            for fp in report["false_positives"]:
                print(f"  {fp['type']} ({fp['cause']}) {fp['description']}")


if __name__ == "__main__":
    main()
