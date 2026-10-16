import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.detectors import Alert, run_all
from src.evaluate import evaluate, format_report, load_truth
from src.parser import parse_file, to_dataframe


def dt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def alert(kind, ip, start, end, users=("u",)):
    return Alert(type=kind, severity="high", mitre_id="T", mitre_name="n", ip=ip,
                 users=tuple(users), start=dt(start), end=dt(end), count=1, description="d")


def truth(kind, ip, start, end, users=("u",), **extra):
    return {"type": kind, "ip": ip, "users": list(users), "start": start, "end": end, **extra}


S, E = "2026-10-01T10:00:00Z", "2026-10-01T10:02:00Z"


def test_perfect_detection():
    r = evaluate([alert("brute_force", "1.1.1.1", S, E)], [truth("brute_force", "1.1.1.1", S, E)])
    assert r["overall"]["recall"] == 1 and r["overall"]["precision"] == 1
    assert r["overall"]["f1"] == 1


def test_missed_attack_lowers_recall():
    r = evaluate([], [truth("brute_force", "1.1.1.1", S, E)])
    assert r["overall"]["recall"] == 0
    assert len(r["missed"]) == 1


def test_unmatched_alert_is_false_positive():
    r = evaluate([alert("brute_force", "9.9.9.9", S, E)], [truth("brute_force", "1.1.1.1", S, E)])
    assert r["overall"]["precision"] == 0 and r["overall"]["false_positives"] == 1


def test_wrong_type_does_not_match():
    r = evaluate([alert("credential_stuffing", "1.1.1.1", S, E)], [truth("brute_force", "1.1.1.1", S, E)])
    assert r["overall"]["recall"] == 0


def test_time_tolerance():
    near = alert("brute_force", "1.1.1.1", "2026-10-01T10:03:00Z", "2026-10-01T10:04:00Z")   # 60 s after end
    far = alert("brute_force", "1.1.1.1", "2026-10-01T12:00:00Z", "2026-10-01T12:01:00Z")
    t = truth("brute_force", "1.1.1.1", S, E)
    assert evaluate([near], [t])["overall"]["recall"] == 1
    assert evaluate([far], [t])["overall"]["recall"] == 0


def test_travel_matches_on_user_not_ip():
    a = alert("impossible_travel", "8.8.8.8", S, E, users=("alice",))
    t = truth("impossible_travel", "7.7.7.7", S, E, users=("alice",))
    assert evaluate([a], [t])["overall"]["recall"] == 1


def test_travel_alert_after_breach_is_corroborating_not_false_positive():
    brute = truth("brute_force", "1.1.1.1", S, E, users=("bob",), breached=True)
    travel = alert("impossible_travel", "1.1.1.1", "2026-10-01T09:00:00Z", E, users=("bob",))
    r = evaluate([alert("brute_force", "1.1.1.1", S, E), travel], [brute])
    assert r["overall"]["corroborating"] == 1
    assert r["overall"]["false_positives"] == 0
    assert r["overall"]["precision"] == 1


def test_travel_alert_without_breach_stays_false_positive():
    brute = truth("brute_force", "1.1.1.1", S, E, users=("bob",), breached=False)
    travel = alert("impossible_travel", "1.1.1.1", "2026-10-01T09:00:00Z", E, users=("bob",))
    r = evaluate([travel], [brute])
    assert r["overall"]["false_positives"] == 1


def test_format_report_contains_totals():
    r = evaluate([alert("brute_force", "1.1.1.1", S, E)], [truth("brute_force", "1.1.1.1", S, E)])
    text = format_report(r, total_events=1000)
    assert "ALL" in text and "F1 score" in text and "per 100k" in text


# ---------- integration: generated logs -> detectors -> score ----------

def test_detectors_catch_every_generated_attack(tmp_path):
    root = Path(__file__).resolve().parent.parent
    subprocess.run([sys.executable, str(root / "src" / "generator.py"), "--days", "7",
                    "--per-day", "2000", "--out", str(tmp_path)], check=True, capture_output=True)
    events, _ = parse_file(tmp_path / "auth.log")
    alerts = run_all(to_dataframe(events))
    report = evaluate(alerts, load_truth(tmp_path / "ground_truth.json"))

    assert report["overall"]["recall"] == 1.0, report["missed"]
    assert report["overall"]["false_positives"] == 0, report["false_positives"]
    for kind, r in report["by_type"].items():
        assert r["recall"] == 1.0, kind


def test_detection_is_stable_across_seeds(tmp_path):
    root = Path(__file__).resolve().parent.parent
    for seed in (1, 7, 123):
        out = tmp_path / str(seed)
        subprocess.run([sys.executable, str(root / "src" / "generator.py"), "--seed", str(seed),
                        "--out", str(out)], check=True, capture_output=True)
        events, _ = parse_file(out / "auth.log")
        report = evaluate(run_all(to_dataframe(events)), load_truth(out / "ground_truth.json"))
        assert report["overall"]["recall"] >= 0.9, (seed, report["missed"])
