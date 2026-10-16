from datetime import datetime, timedelta, timezone

import pytest

from src.detectors import DetectorConfig, run_all, brute_force, credential_stuffing, impossible_travel
from src.detectors.base import haversine_km, merge_windows, sliding_windows
from src.parser import AuthEvent, to_dataframe

T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)

CITIES = {
    "delhi": ("Delhi", 28.61, 77.21),
    "mumbai": ("Mumbai", 19.07, 72.88),
    "ny": ("New York", 40.71, -74.01),
    "london": ("London", 51.51, -0.13),
}


def ev(sec, user="alice", ip="1.2.3.4", result="FAIL", city="delhi"):
    name, lat, lon = CITIES[city]
    return AuthEvent(ts=T0 + timedelta(seconds=sec), user=user, ip=ip, result=result,
                     city=name, lat=lat, lon=lon)


def frame(*events):
    return to_dataframe(list(events))


# ---------- helpers ----------

def test_haversine_delhi_mumbai_about_1150km():
    assert haversine_km(28.61, 77.21, 19.07, 72.88) == pytest.approx(1150, abs=30)


def test_haversine_zero_distance():
    assert haversine_km(10, 10, 10, 10) == 0


def test_sliding_windows_respects_window_and_count():
    assert sliding_windows([0, 1, 2], window=5, min_count=3) == [(0, 2)]
    assert sliding_windows([0, 10, 20], window=5, min_count=2) == []


def test_merge_windows_collapses_overlaps_only():
    assert merge_windows([(0, 5), (3, 8), (20, 25)]) == [(0, 8), (20, 25)]


# ---------- brute force ----------

def test_brute_force_fires_at_threshold():
    df = frame(*[ev(i) for i in range(10)])                 # exactly 10 fails in 9 s
    alerts = brute_force.detect(df)
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.type, a.mitre_id, a.severity) == ("brute_force", "T1110.001", "high")
    assert a.count == 10 and a.users == ("alice",) and a.ip == "1.2.3.4"


def test_brute_force_silent_below_threshold():
    assert brute_force.detect(frame(*[ev(i) for i in range(9)])) == []


def test_brute_force_silent_when_failures_spread_out():
    # 10 failures but one every 60 s -> never 10 inside a 300 s window
    assert brute_force.detect(frame(*[ev(i * 60) for i in range(10)])) == []


def test_brute_force_ignores_successes():
    assert brute_force.detect(frame(*[ev(i, result="SUCCESS") for i in range(50)])) == []


def test_brute_force_is_per_ip_and_user_pair():
    # 6 fails from each of two IPs against the same user: neither reaches 10
    events = [ev(i, ip="1.1.1.1") for i in range(6)] + [ev(i, ip="2.2.2.2") for i in range(6)]
    assert brute_force.detect(frame(*events)) == []


def test_brute_force_one_alert_for_long_episode():
    df = frame(*[ev(i * 2) for i in range(100)])            # 200 s of continuous failures
    assert len(brute_force.detect(df)) == 1


def test_brute_force_two_separate_episodes_two_alerts():
    events = [ev(i) for i in range(12)] + [ev(10_000 + i) for i in range(12)]
    assert len(brute_force.detect(frame(*events))) == 2


def test_brute_force_breach_escalates_to_critical():
    events = [ev(i) for i in range(15)] + [ev(17, result="SUCCESS")]
    a = brute_force.detect(frame(*events))[0]
    assert a.breached and a.severity == "critical"


def test_brute_force_late_success_is_not_breach():
    events = [ev(i) for i in range(15)] + [ev(5000, result="SUCCESS")]
    a = brute_force.detect(frame(*events))[0]
    assert not a.breached and a.severity == "high"


def test_brute_force_threshold_is_configurable():
    cfg = DetectorConfig(bf_threshold=3)
    assert len(brute_force.detect(frame(*[ev(i) for i in range(3)]), cfg)) == 1


# ---------- credential stuffing ----------

def stuffing_events(n_users, per_user=1, ip="9.9.9.9", gap=3):
    out, t = [], 0
    for u in range(n_users):
        for _ in range(per_user):
            out.append(ev(t, user=f"user{u}", ip=ip))
            t += gap
    return out


def test_stuffing_fires_with_enough_distinct_users():
    alerts = credential_stuffing.detect(frame(*stuffing_events(12)))
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.type, a.mitre_id) == ("credential_stuffing", "T1110.004")
    assert len(a.users) >= 10 and a.ip == "9.9.9.9"


def test_stuffing_silent_with_few_users_even_if_many_attempts():
    # 3 users x 30 attempts is brute force territory, not stuffing
    events = [ev(i, user=f"user{i % 3}", ip="9.9.9.9") for i in range(90)]
    assert credential_stuffing.detect(frame(*events)) == []


def test_stuffing_silent_when_users_spread_over_hours():
    assert credential_stuffing.detect(frame(*stuffing_events(12, gap=3600))) == []


def test_stuffing_does_not_trigger_brute_force():
    df = frame(*stuffing_events(20, per_user=2))
    assert brute_force.detect(df) == []
    assert len(credential_stuffing.detect(df)) == 1


def test_brute_force_does_not_trigger_stuffing():
    df = frame(*[ev(i) for i in range(60)])
    assert credential_stuffing.detect(df) == []
    assert len(brute_force.detect(df)) == 1


def test_stuffing_breach_detected_for_any_targeted_user():
    events = stuffing_events(12) + [ev(40, user="user3", ip="9.9.9.9", result="SUCCESS")]
    a = credential_stuffing.detect(frame(*events))[0]
    assert a.breached and a.severity == "critical"


# ---------- impossible travel ----------

def login(sec, city, user="alice", ip="5.5.5.5"):
    return ev(sec, user=user, ip=ip, result="SUCCESS", city=city)


def baseline(user="alice", city="delhi", n=5, ip="5.5.5.5"):
    """Normal history so `city` becomes the user's usual location."""
    return [login(-3_000 + i * 600, city, user=user, ip=ip) for i in range(n)]   # ends 10 min before t=0


def test_impossible_travel_delhi_to_new_york_in_10_minutes():
    df = frame(*baseline(), login(0, "delhi"), login(600, "ny", ip="8.8.8.8"))
    alerts = impossible_travel.detect(df)
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.type, a.mitre_id) == ("impossible_travel", "T1078")
    assert a.ip == "8.8.8.8" and a.users == ("alice",)


def test_plausible_flight_is_not_flagged():
    # London -> New York ~5570 km in 12 h = ~464 km/h
    df = frame(*baseline(city="london"), login(0, "london"), login(12 * 3600, "ny", ip="8.8.8.8"))
    assert impossible_travel.detect(df) == []


def test_same_city_never_flagged():
    df = frame(*baseline(), login(0, "delhi"), login(30, "delhi", ip="8.8.8.8"))
    assert impossible_travel.detect(df) == []


def test_return_to_home_city_does_not_raise_second_alert():
    df = frame(*baseline(), login(0, "ny", ip="8.8.8.8"), login(300, "delhi"))
    alerts = impossible_travel.detect(df)
    assert len(alerts) == 1                 # the jump to NY, not the return home
    assert "New York" in alerts[0].description


def test_failed_logins_are_ignored_for_travel():
    df = frame(*baseline(), login(0, "delhi"), ev(60, ip="8.8.8.8", result="FAIL", city="ny"))
    assert impossible_travel.detect(df) == []


def test_users_are_tracked_independently():
    df = frame(*baseline("alice"), *baseline("bob", city="mumbai", ip="6.6.6.6"),
               login(0, "delhi", "alice"), login(60, "mumbai", "bob", ip="6.6.6.6"))
    assert impossible_travel.detect(df) == []


def test_tiny_distance_below_minimum_ignored():
    cfg = DetectorConfig(travel_min_km=5000)
    df = frame(*baseline(), login(0, "delhi"), login(60, "mumbai", ip="8.8.8.8"))
    assert impossible_travel.detect(df, cfg) == []


# ---------- run_all ----------

def test_run_all_combines_and_sorts_by_time():
    events = ([ev(5000 + i) for i in range(12)]            # brute force later
              + baseline() + [login(0, "delhi"), login(300, "ny", ip="8.8.8.8")])
    alerts = run_all(frame(*events))
    assert [a.type for a in alerts] == ["impossible_travel", "brute_force"]


def test_run_all_on_empty_frame():
    assert run_all(to_dataframe([])) == []


def test_alert_to_dict_is_json_friendly():
    import json
    a = brute_force.detect(frame(*[ev(i) for i in range(10)]))[0]
    d = a.to_dict()
    json.dumps(d)
    assert d["mitre_id"] == "T1110.001" and isinstance(d["users"], list)
