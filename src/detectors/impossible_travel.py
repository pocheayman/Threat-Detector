"""
Impossible-travel detector.   MITRE ATT&CK T1078 - Valid Accounts

Signal: the same account logs in successfully from two places that are too far
apart to travel between in the elapsed time (e.g. Mumbai then New York 9 minutes
later). Usually means stolen credentials or a session token used elsewhere.

Algorithm: per user, walk successful logins in time order; for each consecutive
pair compute haversine distance / elapsed hours and compare with a max speed.

Two guards against noise (say both in interviews):
  * Return legs. Going back to the usual city also looks like impossible travel, so we
    only alert when the NEW login is from a city that is not the user's usual one
    (their most common city). Limitation: that baseline is computed over the whole batch;
    a streaming version would keep a rolling per-user baseline.
  * Alert flooding. Someone on a VPN hops between exit cities every few minutes and
    would raise an alert per hop. Hops by the same user less than `travel_merge_s` apart
    are merged into a single alert that says how many places were involved.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from .base import Alert, DetectorConfig, haversine_km, to_datetime, with_seconds

MITRE_ID = "T1078"
MITRE_NAME = "Valid Accounts"


@dataclass
class _Hop:
    prev_t: float
    t: float
    prev_city: str
    city: str
    km: float
    speed: float
    ip: str


def _alert_for(user: str, hops: list[_Hop]) -> Alert:
    first, last = hops[0], hops[-1]
    if len(hops) == 1:
        minutes = (first.t - first.prev_t) / 60.0
        text = (f"'{user}' logged in from {first.prev_city} then {first.city} "
                f"{minutes:.0f} min later ({first.km:.0f} km, ~{first.speed:.0f} km/h)")
    else:
        places = list(dict.fromkeys([first.prev_city] + [h.city for h in hops]))
        minutes = (last.t - first.prev_t) / 60.0
        text = (f"'{user}' logged in from {len(places)} different cities within {minutes:.0f} min "
                f"({', '.join(places)}). Could be a VPN or shared credentials")
    return Alert(
        type="impossible_travel",
        severity="high",
        mitre_id=MITRE_ID,
        mitre_name=MITRE_NAME,
        ip=first.ip,
        users=(user,),
        start=to_datetime(first.prev_t),
        end=to_datetime(last.t),
        count=len(hops) + 1,                 # number of logins involved
        description=text,
    )


def detect(df: pd.DataFrame, cfg: DetectorConfig = DetectorConfig()) -> list[Alert]:
    df = with_seconds(df)
    successes = df[~df["failed"]].sort_values("t")
    alerts: list[Alert] = []

    for user, g in successes.groupby("user", sort=False):
        home_city = g["city"].mode().iloc[0]
        hops: list[_Hop] = []
        prev = None
        for row in g.itertuples(index=False):
            if prev is not None and row.city != prev.city and row.city != home_city:
                km = haversine_km(prev.lat, prev.lon, row.lat, row.lon)
                if km >= cfg.travel_min_km:
                    hours = max(row.t - prev.t, 1.0) / 3600.0   # avoid divide-by-zero
                    speed = km / hours
                    if speed > cfg.travel_max_kmh:
                        hops.append(_Hop(prev.t, row.t, prev.city, row.city, km, speed, str(row.ip)))
            prev = row

        group: list[_Hop] = []
        for hop in hops:
            if group and hop.prev_t - group[-1].t > cfg.travel_merge_s:
                alerts.append(_alert_for(str(user), group))
                group = []
            group.append(hop)
        if group:
            alerts.append(_alert_for(str(user), group))
    return alerts
