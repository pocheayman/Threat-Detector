"""
Train the anomaly model on a clean baseline log and save it.

    python -m src.ml.train data/baseline/auth.log           # train on your own clean history
    python -m src.ml.train --auto                           # simulate a clean baseline, then train
    python -m src.ml.train --auto --out models/iforest.joblib --quantile 0.999
    python -m src.ml.train --auto --trusted 115.249.0.0/16     # keep known office ranges out of training
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ..parser import parse_file, to_dataframe
from .model import train_model

DEFAULT_MODEL = "models/iforest.joblib"


def simulated_baseline(seed: int = 7, days: int = 28, nat_bursts: int = 12):
    """A clean 'last month of normal traffic': no attacks, but with the harmless oddities
    real networks have (a shared office IP that sees login storms, people on a VPN)."""
    from ..generator import generate
    from ..parser import parse_lines

    data = generate(seed=seed, days=days, brute=0, stuffing=0, travel=0,
                    nat_bursts=nat_bursts, vpn_users=3)
    return to_dataframe(list(parse_lines(data["lines"])))


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the Isolation Forest anomaly detector")
    ap.add_argument("log", nargs="?", help="clean baseline auth log (omit with --auto)")
    ap.add_argument("--auto", action="store_true", help="simulate a clean baseline instead of reading a log")
    ap.add_argument("--out", default=DEFAULT_MODEL)
    ap.add_argument("--quantile", type=float, default=0.999,
                    help="alert threshold as a percentile of the training scores")
    ap.add_argument("--trusted", default="",
                    help="comma-separated CIDR ranges to exclude from training, e.g. 115.249.0.0/16")
    ap.add_argument("--min-fails", type=int, default=8)
    ap.add_argument("--seed", type=int, default=7, help="seed for the simulated baseline")
    args = ap.parse_args()

    if args.auto:
        df = simulated_baseline(args.seed)
        source = f"simulated baseline (seed {args.seed})"
    elif args.log:
        events, stats = parse_file(args.log)
        df = to_dataframe(events)
        source = f"{args.log} ({stats.parsed} events)"
    else:
        ap.error("give a log file or use --auto")

    trusted = tuple(n.strip() for n in args.trusted.split(",") if n.strip())
    if args.auto and not trusted:
        from ..generator import OFFICE_NETWORK
        trusted = (OFFICE_NETWORK,)          # the simulated office range
    model = train_model(df, quantile=args.quantile, min_fails=args.min_fails, trusted_networks=trusted)
    model.save(args.out)
    print(f"Trained on {source}: {model.train_rows} (ip, hour) rows, "
          f"alert threshold {model.threshold:.3f} (the {args.quantile:.2%} percentile of training scores)")
    print(f"Saved model to {Path(args.out)}")


if __name__ == "__main__":
    main()
