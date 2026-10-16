"""
Scorer: compares detector alerts with ground_truth.json.

Matching rules
  * An injected attack is DETECTED if at least one alert overlaps it in time
    (+/- tolerance) and refers to the same entity:
      brute_force / credential_stuffing -> same source IP
      impossible_travel                 -> same user
    A rule alert must have the same type. A machine-learning alert ("anomalous_activity")
    does not say which kind of attack it saw, so it may match either IP-based type.
  * An alert that matches no injected attack is a FALSE POSITIVE, unless it is
    "corroborating": the attacker's own login after a brute-force breach, which is real
    malicious activity that the answer key files under the brute-force attack.

Metrics
  recall    = detected attacks / all attacks          ("did we catch them?")
  precision = correct alerts / all alerts             ("are alerts trustworthy?")

If benign_scenarios.json is supplied, each false positive is attributed to the harmless
scenario that caused it (shared office, VPN user), otherwise it is "unexplained".
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .detectors.base import Alert

TYPES = ("brute_force", "credential_stuffing", "impossible_travel")
IP_TYPES = ("brute_force", "credential_stuffing")
ML_TYPE = "anomalous_activity"
ALERT_TYPES = TYPES + (ML_TYPE,)

LABELS = {
    "brute_force": "Brute force",
    "credential_stuffing": "Credential stuffing",
    "impossible_travel": "Impossible travel",
    ML_TYPE: "ML anomaly",
}


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_json(path: str | Path) -> list[dict]:
    p = Path(path)
    return json.loads(p.read_text()) if p.exists() else []


def load_truth(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text())


def _overlaps(alert: Alert, item: dict, tolerance_s: float) -> bool:
    tol = timedelta(seconds=tolerance_s)
    return not (alert.end < _parse(item["start"]) - tol or alert.start > _parse(item["end"]) + tol)


def matches(alert: Alert, truth: dict, tolerance_s: float = 120.0) -> bool:
    if alert.type == ML_TYPE:
        if truth["type"] not in IP_TYPES:
            return False
    elif alert.type != truth["type"]:
        return False
    if not _overlaps(alert, truth, tolerance_s):
        return False
    if truth["type"] == "impossible_travel":
        return bool(set(alert.users) & set(truth["users"]))
    return alert.ip == truth["ip"]


def corroborates(alert: Alert, truth: dict, tolerance_s: float = 120.0) -> bool:
    """An impossible-travel alert on the attacker's own successful login after a
    brute-force breach is real malicious activity, just labelled under the
    brute_force attack in the answer key. Count it as corroborating, not a false positive."""
    if alert.type != "impossible_travel" or truth["type"] != "brute_force" or not truth.get("breached"):
        return False
    tol = timedelta(seconds=tolerance_s)
    return (alert.ip == truth["ip"]
            and _parse(truth["start"]) - tol <= alert.end <= _parse(truth["end"]) + tol)


def explain_false_positive(alert: Alert, benign: list[dict], tolerance_s: float = 600.0) -> str:
    """Name the harmless scenario behind a false alarm, if there is one."""
    for b in benign:
        if not _overlaps(alert, b, tolerance_s):
            continue
        if b["type"] == "benign_nat_burst" and alert.ip == b["ip"]:
            return "shared office login storm"
        if b["type"] == "benign_vpn" and alert.type == "impossible_travel" and set(alert.users) & set(b["users"]):
            return "VPN user"
    return "unexplained"


def _ratio(num: int, den: int) -> float:
    return num / den if den else 0.0


def evaluate(alerts: list[Alert], truth: list[dict], tolerance_s: float = 120.0,
             benign: Optional[list[dict]] = None) -> dict:
    benign = benign or []

    # ---- recall: which attacks did ANY alert catch? ----
    detected_flags = [any(matches(a, t, tolerance_s) for a in alerts) for t in truth]
    by_type = {}
    for kind in TYPES:
        idx = [i for i, t in enumerate(truth) if t["type"] == kind]
        caught = sum(detected_flags[i] for i in idx)
        by_type[kind] = {"attacks": len(idx), "detected": caught, "missed": len(idx) - caught,
                         "recall": _ratio(caught, len(idx))}

    variants = {}
    for name, pick in (("fast", lambda t: not t.get("slow")), ("slow", lambda t: bool(t.get("slow")))):
        idx = [i for i, t in enumerate(truth) if pick(t)]
        caught = sum(detected_flags[i] for i in idx)
        variants[name] = {"attacks": len(idx), "detected": caught, "recall": _ratio(caught, len(idx))}

    # ---- precision: which alerts were right? ----
    by_alert_type, false_positives, causes = {}, [], {}
    correct_total = corroborating_total = 0
    for kind in ALERT_TYPES:
        a_items = [a for a in alerts if a.type == kind]
        good = [a for a in a_items if any(matches(a, t, tolerance_s) for t in truth)]
        corr = [a for a in a_items if a not in good and any(corroborates(a, t, tolerance_s) for t in truth)]
        bad = [a for a in a_items if a not in good and a not in corr]
        by_alert_type[kind] = {
            "alerts": len(a_items), "correct": len(good) + len(corr), "corroborating": len(corr),
            "false_positives": len(bad), "precision": _ratio(len(good) + len(corr), len(a_items)),
        }
        correct_total += len(good) + len(corr)
        corroborating_total += len(corr)
        for a in bad:
            cause = explain_false_positive(a, benign)
            causes[cause] = causes.get(cause, 0) + 1
            false_positives.append({**a.to_dict(), "cause": cause})

    detected = sum(detected_flags)
    recall, precision = _ratio(detected, len(truth)), _ratio(correct_total, len(alerts))
    return {
        "by_type": by_type,
        "by_alert_type": by_alert_type,
        "variants": variants,
        "false_positive_causes": causes,
        "missed": [t for t, ok in zip(truth, detected_flags) if not ok],
        "false_positives": false_positives,
        "overall": {
            "attacks": len(truth), "detected": detected, "alerts": len(alerts),
            "corroborating": corroborating_total,
            "false_positives": len(alerts) - correct_total,
            "recall": recall, "precision": precision,
            "f1": _ratio(2 * precision * recall, precision + recall) if (precision + recall) else 0.0,
        },
    }


def format_report(report: dict, total_events: int | None = None) -> str:
    lines = ["Recall: how many injected attacks were caught",
             f"{'attack type':<22}{'attacks':>8}{'caught':>8}{'recall':>9}", "-" * 47]
    for kind, r in report["by_type"].items():
        lines.append(f"{LABELS[kind]:<22}{r['attacks']:>8}{r['detected']:>8}{r['recall']:>9.0%}")
    v = report["variants"]
    if v["slow"]["attacks"]:
        lines.append(f"{'  loud attacks':<22}{v['fast']['attacks']:>8}{v['fast']['detected']:>8}{v['fast']['recall']:>9.0%}")
        lines.append(f"{'  low-and-slow':<22}{v['slow']['attacks']:>8}{v['slow']['detected']:>8}{v['slow']['recall']:>9.0%}")
    o = report["overall"]
    lines.append("-" * 47)
    lines.append(f"{'ALL':<22}{o['attacks']:>8}{o['detected']:>8}{o['recall']:>9.0%}")

    lines += ["", "Precision: how many alerts were right",
              f"{'alert source':<22}{'alerts':>8}{'correct':>9}{'false':>7}{'precision':>11}", "-" * 57]
    for kind, r in report["by_alert_type"].items():
        if r["alerts"]:
            lines.append(f"{LABELS[kind]:<22}{r['alerts']:>8}{r['correct']:>9}{r['false_positives']:>7}{r['precision']:>11.0%}")
    lines.append("-" * 57)
    lines.append(f"{'ALL':<22}{o['alerts']:>8}{o['alerts'] - o['false_positives']:>9}{o['false_positives']:>7}{o['precision']:>11.0%}")
    lines.append(f"F1 score: {o['f1']:.2f}")
    if o.get("corroborating"):
        lines.append(f"({o['corroborating']} impossible-travel alerts are the attacker's own login after a "
                     f"brute-force breach: real activity, counted as correct)")
    if report["false_positive_causes"]:
        why = ", ".join(f"{n} from {c}" for c, n in sorted(report["false_positive_causes"].items()))
        lines.append(f"False alarms by cause: {why}")
    if total_events:
        fp_rate = o["false_positives"] / max(total_events, 1)
        lines.append(f"Events scanned: {total_events}  |  false alerts per 100k events: {fp_rate * 100000:.1f}")
    return "\n".join(lines)
