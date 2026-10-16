import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.parser import AuthEvent, iter_events, parse_file, parse_line, to_dataframe, ParseStats

GOOD = ("2026-10-12T09:15:32Z auth user=alice ip=49.37.12.8 result=SUCCESS "
        "city=Bengaluru lat=12.97 lon=77.59")
GOOD_FAIL = ("2026-10-12T09:15:40Z auth user=bob ip=203.0.113.9 result=FAIL "
             "city=New York lat=40.71 lon=-74.01")


# ---------- parse_line: valid input ----------

def test_parses_valid_success_line():
    e = parse_line(GOOD)
    assert e == AuthEvent(
        ts=datetime(2026, 10, 12, 9, 15, 32, tzinfo=timezone.utc),
        user="alice", ip="49.37.12.8", result="SUCCESS",
        city="Bengaluru", lat=12.97, lon=77.59,
    )
    assert e.failed is False


def test_parses_fail_line_and_city_with_space():
    e = parse_line(GOOD_FAIL)
    assert e.failed is True
    assert e.city == "New York"
    assert e.lon == -74.01


def test_timestamp_is_timezone_aware_utc():
    assert parse_line(GOOD).ts.tzinfo == timezone.utc


def test_trailing_newline_and_whitespace_ok():
    assert parse_line("  " + GOOD + "\n") is not None


def test_result_is_case_insensitive():
    assert parse_line(GOOD.replace("SUCCESS", "success")).result == "SUCCESS"


# ---------- parse_line: malformed input must return None, never raise ----------

@pytest.mark.parametrize("bad", [
    "",
    "   ",
    "garbage",
    "2026-10-12T09:15:32Z",                                   # no fields
    "2026-10-12T09:15:32Z auth",                              # no fields
    "not-a-date auth user=a ip=1.2.3.4 result=FAIL city=X lat=1 lon=1",
    "2026-13-45T99:99:99Z auth user=a ip=1.2.3.4 result=FAIL city=X lat=1 lon=1",
    "2026-10-12T09:15:32Z sshd user=a ip=1.2.3.4 result=FAIL city=X lat=1 lon=1",  # wrong source
    "2026-10-12T09:15:32Z auth ip=1.2.3.4 result=FAIL city=X lat=1 lon=1",          # missing user
    "2026-10-12T09:15:32Z auth user=a ip=999.1.1.1 result=FAIL city=X lat=1 lon=1",  # bad ip
    "2026-10-12T09:15:32Z auth user=a ip=1.2.3.4 result=MAYBE city=X lat=1 lon=1",  # bad result
    "2026-10-12T09:15:32Z auth user=a ip=1.2.3.4 result=FAIL city=X lat=abc lon=1",  # non-numeric
    "2026-10-12T09:15:32Z auth user=a ip=1.2.3.4 result=FAIL city=X lat=95 lon=1",   # lat range
    "2026-10-12T09:15:32Z auth user=a ip=1.2.3.4 result=FAIL city=X lat=1 lon=181",  # lon range
    "2026-10-12T09:15:32Z auth user= ip=1.2.3.4 result=FAIL city=X lat=1 lon=1",     # empty user
])
def test_malformed_lines_return_none(bad):
    assert parse_line(bad) is None


def test_duplicate_keys_are_rejected_as_log_injection():
    # attacker-chosen username tries to smuggle in a fake "result=SUCCESS" field
    forged = ("2026-10-12T09:15:40Z auth user=bob result=SUCCESS ip=203.0.113.9 result=FAIL "
              "city=Mumbai lat=19.07 lon=72.88")
    assert parse_line(forged) is None


def test_html_in_username_is_kept_verbatim():
    line = GOOD.replace("user=alice", "user=<b>hi</b><script>alert(1)</script>")
    assert parse_line(line).user == "<b>hi</b><script>alert(1)</script>"


# ---------- file level ----------

def _write(tmp_path, lines):
    p = tmp_path / "auth.log"
    p.write_text("\n".join(lines) + "\n")
    return p


def test_parse_file_counts_good_and_bad(tmp_path):
    p = _write(tmp_path, [GOOD, "garbage line", GOOD_FAIL, "", "2026-10-12T09:15:32Z auth"])
    events, stats = parse_file(p)
    assert len(events) == 2
    assert stats.total == 4          # blank lines are not counted
    assert stats.parsed == 2
    assert stats.rejected == 2
    assert stats.reject_rate == 0.5


def test_iter_events_is_lazy_generator(tmp_path):
    p = _write(tmp_path, [GOOD, GOOD_FAIL])
    stats = ParseStats()
    it = iter_events(p, stats)
    assert stats.total == 0          # nothing read yet
    next(it)
    assert stats.total == 1


def test_non_utf8_bytes_do_not_crash(tmp_path):
    p = tmp_path / "auth.log"
    p.write_bytes(GOOD.encode() + b"\n\xff\xfe broken \x00\n")
    events, stats = parse_file(p)
    assert len(events) == 1 and stats.rejected == 1


# ---------- DataFrame ----------

def test_dataframe_sorted_and_typed(tmp_path):
    # deliberately out of order
    p = _write(tmp_path, [GOOD_FAIL.replace("09:15:40", "10:00:00"), GOOD])
    events, _ = parse_file(p)
    df = to_dataframe(events)
    assert list(df["user"]) == ["alice", "bob"]            # sorted by ts
    assert str(df["ts"].dt.tz) == "UTC"
    assert df["failed"].tolist() == [False, True]
    assert df["lat"].dtype.kind == "f"


def test_dataframe_empty_has_columns():
    df = to_dataframe([])
    assert df.empty
    assert {"ts", "user", "ip", "result", "city", "lat", "lon"} <= set(df.columns)


# ---------- integration with the generator ----------

def test_parses_every_generated_line(tmp_path):
    root = Path(__file__).resolve().parent.parent
    subprocess.run(
        [sys.executable, str(root / "src" / "generator.py"),
         "--days", "2", "--per-day", "300", "--out", str(tmp_path)],
        check=True, capture_output=True,
    )
    events, stats = parse_file(tmp_path / "auth.log")
    assert stats.rejected == 0
    assert stats.parsed == stats.total == len(events)

    truth = json.loads((tmp_path / "ground_truth.json").read_text())
    df = to_dataframe(events)
    # every attacker IP from the answer key shows up in the parsed data
    for attack in truth:
        if attack["type"] in ("brute_force", "credential_stuffing"):
            assert attack["ip"] in set(df["ip"])
