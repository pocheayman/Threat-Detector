"""
Synthetic authentication-log generator.

Produces:
  data/auth.log             - what your detectors will read
  data/ground_truth.json    - answer key: every injected ATTACK (used to score detectors)
  data/benign_scenarios.json- harmless-but-suspicious-looking activity (hard mode only);
                              used to explain why a detector raised a false alarm

Log line format (key=value, easy to parse):
  2026-10-12T09:15:32Z auth user=alice ip=49.37.12.8 result=SUCCESS city=Bengaluru lat=12.97 lon=77.59

Easy mode (default): loud attacks, clean background traffic.
Hard mode (--hard) adds what makes real detection difficult:
  * low-and-slow brute force and password spraying, spread out to stay under rate thresholds
  * benign shared-office bursts: one IP, many employees mistyping passwords on Monday morning
  * benign VPN users: one account appearing from many cities within minutes

Everything here is simulated. No real systems are touched.
"""

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# (city, lat, lon, ip prefix) - where legitimate users live / travel from
CITIES = [
    ("Bengaluru", 12.97, 77.59, "49.37"),
    ("Mumbai", 19.07, 72.88, "103.21"),
    ("Delhi", 28.61, 77.21, "117.99"),
    ("London", 51.51, -0.13, "81.2"),
    ("New York", 40.71, -74.01, "72.229"),
    ("Singapore", 1.35, 103.82, "175.41"),
    ("Sydney", -33.87, 151.21, "1.128"),
    ("Sao Paulo", -23.55, -46.63, "177.71"),
]

USERS = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
    "ivan", "judy", "mallory", "niaj", "olivia", "peggy", "rupert", "sybil",
    "trent", "victor", "walter", "zoe",
]

# Common usernames an attacker would spray
COMMON_USERNAMES = USERS + [
    "admin", "root", "test", "guest", "user", "oracle", "postgres", "ubuntu",
    "support", "info", "backup", "ftp", "mysql", "git", "jenkins", "deploy",
]

# Attacker IPs come from documentation ranges (reserved, never real hosts)
ATTACKER_RANGES = ["203.0.113", "198.51.100", "192.0.2"]

# The simulated company's office egress range. Login storms from here are benign.
OFFICE_NETWORK = "115.249.0.0/16"

# What --hard switches on when a count is not given explicitly
HARD_DEFAULTS = {"slow_brute": 4, "slow_stuffing": 3, "nat_bursts": 3, "vpn_users": 3}


def fmt(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_line(ts, user, ip, result, city):
    name, lat, lon, _ = city
    return (
        f"{fmt(ts)} auth user={user} ip={ip} result={result} "
        f"city={name} lat={lat} lon={lon}"
    )


def random_ip(prefix, rng):
    parts = prefix.split(".")
    while len(parts) < 4:
        parts.append(str(rng.randint(1, 254)))
    return ".".join(parts)


def attacker_ip(rng):
    return f"{rng.choice(ATTACKER_RANGES)}.{rng.randint(1, 254)}"


def build_user_profiles(rng):
    """Each user has one home city and a stable IP they normally use."""
    profiles = {}
    for user in USERS:
        city = rng.choice(CITIES)
        profiles[user] = {"city": city, "ip": random_ip(city[3], rng)}
    return profiles


def random_start(rng, start, days, hour_lo=0, hour_hi=23):
    return start + timedelta(
        days=rng.randint(0, days - 1), hours=rng.randint(hour_lo, hour_hi),
        minutes=rng.randint(0, 59),
    )


def normal_traffic(rng, profiles, start, days, per_day):
    events = []
    for day in range(days):
        for _ in range(per_day):
            user = rng.choice(USERS)
            prof = profiles[user]
            # office-hours-ish distribution
            hour = int(min(23, max(0, rng.gauss(13, 4))))
            ts = start + timedelta(
                days=day, hours=hour,
                minutes=rng.randint(0, 59), seconds=rng.randint(0, 59),
            )
            # users occasionally mistype a password
            result = "FAIL" if rng.random() < 0.04 else "SUCCESS"
            events.append((ts, make_line(ts, user, prof["ip"], result, prof["city"])))
    return events


# ---------------------------------------------------------------- attacks (easy)

def brute_force(rng, start, days, profiles):
    """One IP hammers one account: many FAILs in a short window."""
    ts = start + timedelta(
        days=rng.randint(0, days - 1), hours=rng.randint(0, 23),
        minutes=rng.randint(0, 59),
    )
    ip = attacker_ip(rng)
    user = rng.choice(USERS)
    city = rng.choice(CITIES)
    n = rng.randint(30, 80)
    events, t = [], ts
    for _ in range(n):
        t += timedelta(seconds=rng.randint(1, 4))
        events.append((t, make_line(t, user, ip, "FAIL", city)))
    # sometimes the attacker eventually gets in
    breached = rng.random() < 0.5
    if breached:
        t += timedelta(seconds=2)
        events.append((t, make_line(t, user, ip, "SUCCESS", city)))
    return events, {
        "type": "brute_force", "ip": ip, "users": [user],
        "start": fmt(ts), "end": fmt(t), "attempts": len(events),
        "breached": breached,
    }


def credential_stuffing(rng, start, days, profiles):
    """One IP tries many different usernames, a few attempts each."""
    ts = start + timedelta(
        days=rng.randint(0, days - 1), hours=rng.randint(0, 23),
        minutes=rng.randint(0, 59),
    )
    ip = attacker_ip(rng)
    city = rng.choice(CITIES)
    targets = rng.sample(COMMON_USERNAMES, rng.randint(15, 30))
    events, t = [], ts
    for user in targets:
        for _ in range(rng.randint(1, 3)):
            t += timedelta(seconds=rng.randint(2, 10))
            events.append((t, make_line(t, user, ip, "FAIL", city)))
    return events, {
        "type": "credential_stuffing", "ip": ip, "users": targets,
        "start": fmt(ts), "end": fmt(t), "attempts": len(events),
    }


def impossible_travel(rng, start, days, profiles):
    """Same user logs in from two far-apart cities minutes apart."""
    user = rng.choice(USERS)
    home = profiles[user]["city"]
    far = rng.choice([c for c in CITIES if c[0] != home[0]])
    ts = start + timedelta(
        days=rng.randint(0, days - 1), hours=rng.randint(8, 18),
        minutes=rng.randint(0, 59),
    )
    t2 = ts + timedelta(minutes=rng.randint(3, 20))
    ip2 = random_ip(far[3], rng)
    events = [
        (ts, make_line(ts, user, profiles[user]["ip"], "SUCCESS", home)),
        (t2, make_line(t2, user, ip2, "SUCCESS", far)),
    ]
    return events, {
        "type": "impossible_travel", "ip": ip2, "users": [user],
        "start": fmt(ts), "end": fmt(t2), "from": home[0], "to": far[0],
    }


# ---------------------------------------------------------------- attacks (hard)

def slow_brute_force(rng, start, days, profiles):
    """Low and slow: one failure every ~1-2 minutes for an hour or more.
    Stays below any 'N failures in a few minutes' threshold."""
    ts = random_start(rng, start, days, 0, 20)
    ip, user, city = attacker_ip(rng), rng.choice(USERS), rng.choice(CITIES)
    events, t = [], ts
    for _ in range(rng.randint(24, 40)):
        t += timedelta(seconds=rng.randint(70, 130))
        events.append((t, make_line(t, user, ip, "FAIL", city)))
    breached = rng.random() < 0.3
    if breached:
        t += timedelta(seconds=rng.randint(70, 130))
        events.append((t, make_line(t, user, ip, "SUCCESS", city)))
    return events, {
        "type": "brute_force", "slow": True, "ip": ip, "users": [user],
        "start": fmt(ts), "end": fmt(t), "attempts": len(events), "breached": breached,
    }


def slow_password_spray(rng, start, days, profiles):
    """Password spraying at one attempt per ~2 minutes across many usernames:
    never 10 distinct usernames inside a 10-minute window."""
    ts = random_start(rng, start, days, 0, 20)
    ip, city = attacker_ip(rng), rng.choice(CITIES)
    targets = rng.sample(COMMON_USERNAMES, rng.randint(20, 30))
    events, t = [], ts
    for user in targets:
        t += timedelta(seconds=rng.randint(90, 150))
        events.append((t, make_line(t, user, ip, "FAIL", city)))
    return events, {
        "type": "credential_stuffing", "slow": True, "ip": ip, "users": targets,
        "start": fmt(ts), "end": fmt(t), "attempts": len(events),
    }


# ---------------------------------------------------------------- benign noise (hard)

def nat_burst(rng, start, days, profiles):
    """BENIGN: Monday-morning login storm from one shared office IP. Many employees
    mistype passwords within minutes, then get in. Looks exactly like credential stuffing
    to a naive rule. (Each login carries the employee's own city to keep the simulation
    focused on the one effect.)"""
    day = rng.randint(0, days - 1)
    ts = start + timedelta(days=day, hours=rng.randint(8, 10), minutes=rng.randint(0, 40))
    ip = f"115.249.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
    staff = rng.sample(USERS, rng.randint(14, 20))
    events, t = [], ts
    for user in staff:
        city = profiles[user]["city"]
        for _ in range(rng.randint(1, 3)):
            t += timedelta(seconds=rng.randint(3, 15))
            events.append((t, make_line(t, user, ip, "FAIL", city)))
        t += timedelta(seconds=rng.randint(3, 15))
        events.append((t, make_line(t, user, ip, "SUCCESS", city)))
    return events, {
        "type": "benign_nat_burst", "ip": ip, "users": staff, "start": fmt(ts), "end": fmt(t),
    }


def vpn_session(rng, start, days, profiles, user):
    """BENIGN: one employee on a commercial VPN; exit nodes change city every few minutes."""
    ts = random_start(rng, start, days, 8, 18)
    events, t = [], ts
    for _ in range(rng.randint(4, 6)):
        city = rng.choice(CITIES)
        events.append((t, make_line(t, user, random_ip(city[3], rng), "SUCCESS", city)))
        t += timedelta(minutes=rng.randint(4, 15))
    return events, {
        "type": "benign_vpn", "ip": None, "users": [user], "start": fmt(ts), "end": fmt(t),
    }


# ---------------------------------------------------------------- orchestration

def generate(seed=42, days=7, per_day=2000, brute=5, stuffing=4, travel=6,
             slow_brute=0, slow_stuffing=0, nat_bursts=0, vpn_users=0):
    """Build a dataset in memory. Returns {'lines', 'truth', 'benign'}.

    The random calls for the easy scenarios happen in the same order as before, and the
    hard ones come afterwards, so default output for a given seed never changes.
    """
    rng = random.Random(seed)
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    profiles = build_user_profiles(rng)

    events = normal_traffic(rng, profiles, start, days, per_day)
    truth, benign = [], []
    for count, fn in [(brute, brute_force), (stuffing, credential_stuffing), (travel, impossible_travel)]:
        for _ in range(count):
            evs, label = fn(rng, start, days, profiles)
            events.extend(evs)
            truth.append(label)

    for count, fn in [(slow_brute, slow_brute_force), (slow_stuffing, slow_password_spray)]:
        for _ in range(count):
            evs, label = fn(rng, start, days, profiles)
            events.extend(evs)
            truth.append(label)

    for _ in range(nat_bursts):
        evs, label = nat_burst(rng, start, days, profiles)
        events.extend(evs)
        benign.append(label)

    if vpn_users:
        for user in rng.sample(USERS, min(vpn_users, len(USERS))):
            for _ in range(2):                      # two VPN sessions each
                evs, label = vpn_session(rng, start, days, profiles, user)
                events.extend(evs)
                benign.append(label)

    events.sort(key=lambda e: e[0])
    return {"lines": [line for _, line in events], "truth": truth, "benign": benign}


def main():
    ap = argparse.ArgumentParser(description="Generate synthetic auth logs")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--per-day", type=int, default=2000,
                    help="normal login events per day")
    ap.add_argument("--brute", type=int, default=5)
    ap.add_argument("--stuffing", type=int, default=4)
    ap.add_argument("--travel", type=int, default=6)
    ap.add_argument("--hard", action="store_true",
                    help="add slow attacks and benign look-alikes (shared office, VPN users)")
    ap.add_argument("--slow-brute", type=int, default=None)
    ap.add_argument("--slow-stuffing", type=int, default=None)
    ap.add_argument("--nat-bursts", type=int, default=None)
    ap.add_argument("--vpn-users", type=int, default=None)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data")
    args = ap.parse_args()

    def pick(name):
        value = getattr(args, name)
        if value is not None:
            return value
        return HARD_DEFAULTS[name] if args.hard else 0

    result = generate(
        seed=args.seed, days=args.days, per_day=args.per_day,
        brute=args.brute, stuffing=args.stuffing, travel=args.travel,
        slow_brute=pick("slow_brute"), slow_stuffing=pick("slow_stuffing"),
        nat_bursts=pick("nat_bursts"), vpn_users=pick("vpn_users"),
    )

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "auth.log").write_text("\n".join(result["lines"]) + "\n")
    (out / "ground_truth.json").write_text(json.dumps(result["truth"], indent=2))
    if result["benign"]:
        (out / "benign_scenarios.json").write_text(json.dumps(result["benign"], indent=2))

    truth = result["truth"]
    print(f"Wrote {len(result['lines'])} events to {out / 'auth.log'}")
    print(f"Injected {len(truth)} attacks -> {out / 'ground_truth.json'}")
    for kind in ("brute_force", "credential_stuffing", "impossible_travel"):
        n = sum(1 for t in truth if t["type"] == kind)
        slow = sum(1 for t in truth if t["type"] == kind and t.get("slow"))
        print(f"  {kind}: {n}" + (f" ({slow} low-and-slow)" if slow else ""))
    if result["benign"]:
        print(f"Added {len(result['benign'])} benign look-alike scenarios -> {out / 'benign_scenarios.json'}")


if __name__ == "__main__":
    main()
