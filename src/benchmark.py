"""
Benchmark: rules vs ML vs hybrid on HELD-OUT seeds.

    python -m src.benchmark                      # seeds 1-5, writes docs/benchmark.{json,md}

Honesty rules baked in:
  * the model is trained once on a clean simulated month (seed 7), never on test data
  * tuning was done on development seeds 101-103; the seeds here (1-5) were never looked at
  * every number comes from synthetic logs with injected attacks; see docs for limits
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detectors import DetectorConfig
from .evaluate import evaluate
from .generator import OFFICE_NETWORK, generate
from .ml import train_model
from .ml.train import simulated_baseline
from .parser import parse_lines, to_dataframe
from .pipeline import detect
from .detectors import run_all

SEEDS = (1, 2, 3, 4, 5)


def _tally(reports: list[dict]) -> dict:
    s = lambda f: sum(f(r) for r in reports)
    attacks, caught = s(lambda r: r["overall"]["attacks"]), s(lambda r: r["overall"]["detected"])
    alerts, fps = s(lambda r: r["overall"]["alerts"]), s(lambda r: r["overall"]["false_positives"])
    slow_n, slow_c = s(lambda r: r["variants"]["slow"]["attacks"]), s(lambda r: r["variants"]["slow"]["detected"])
    fast_n, fast_c = s(lambda r: r["variants"]["fast"]["attacks"]), s(lambda r: r["variants"]["fast"]["detected"])
    rec = caught / attacks if attacks else 0.0
    prec = (alerts - fps) / alerts if alerts else 0.0
    causes = {}
    for r in reports:
        for k, v in r["false_positive_causes"].items():
            causes[k] = causes.get(k, 0) + v
    return {"attacks": attacks, "detected": caught, "alerts": alerts, "false_positives": fps,
            "recall": rec, "precision": prec, "f1": 2 * rec * prec / (rec + prec) if rec + prec else 0.0,
            "fast_recall": fast_c / fast_n if fast_n else 0.0, "slow_recall": slow_c / slow_n if slow_n else 0.0,
            "fast": [fast_c, fast_n], "slow": [slow_c, slow_n], "fp_causes": causes}


def run(seeds=SEEDS) -> dict:
    base = simulated_baseline()
    model = train_model(base, trusted_networks=(OFFICE_NETWORK,))
    results = {}
    for scenario, hard in (("easy", False), ("hard", True)):
        data = {s: generate(seed=s, **({"slow_brute": 4, "slow_stuffing": 3, "nat_bursts": 3, "vpn_users": 3}
                                       if hard else {})) for s in seeds}
        frames = {s: to_dataframe(list(parse_lines(d["lines"]))) for s, d in data.items()}
        for name, use_model, trusted in (("rules", False, ()), ("ml", True, (OFFICE_NETWORK,)),
                                         ("hybrid", True, ()), ("hybrid + allowlist", True, (OFFICE_NETWORK,))):
            reports = []
            for s in seeds:
                cfg = DetectorConfig(trusted_networks=trusted)
                if name == "rules":
                    alerts = run_all(frames[s], cfg)
                elif name == "ml":
                    alerts = model.detect(frames[s], cfg)
                else:
                    alerts = detect(frames[s], cfg, model)
                reports.append(evaluate(alerts, data[s]["truth"], benign=data[s].get("benign", [])))
            results[f"{scenario}/{name}"] = _tally(reports)
        results["_events_" + scenario] = sum(len(d["lines"]) for d in data.values())
    return results


def markdown(res: dict, seeds=SEEDS) -> str:
    out = [f"# Benchmark (held-out seeds {seeds[0]}-{seeds[-1]}, synthetic data)\n"]
    for scenario in ("easy", "hard"):
        out += [f"\n## {scenario.capitalize()} data  ({res['_events_' + scenario]:,} events)\n",
                "| detector | attacks caught | recall | loud recall | low-and-slow recall | alerts | false alarms | precision | F1 |",
                "|---|---|---|---|---|---|---|---|---|"]
        for k, r in res.items():
            if not k.startswith(scenario + "/"):
                continue
            slow = f"{r['slow'][0]}/{r['slow'][1]} ({r['slow_recall']:.0%})" if r["slow"][1] else "n/a"
            out.append(f"| {k.split('/')[1]} | {r['detected']}/{r['attacks']} | {r['recall']:.0%} | "
                       f"{r['fast'][0]}/{r['fast'][1]} ({r['fast_recall']:.0%}) | {slow} | {r['alerts']} | "
                       f"{r['false_positives']} | {r['precision']:.0%} | {r['f1']:.2f} |")
    return "\n".join(out) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="docs/benchmark")
    args = ap.parse_args()
    res = run()
    md = markdown(res)
    print(md)
    for k, r in res.items():
        if not k.startswith("_") and r["fp_causes"]:
            print(f"{k}: false alarms by cause {r['fp_causes']}")
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out + ".json").write_text(json.dumps(res, indent=2))
    Path(args.out + ".md").write_text(md)


if __name__ == "__main__":
    main()
