"""
SQLite storage for alerts.

Why SQLite: zero setup, one file, ships with Python - ideal for a single-node
tool. The access layer is small and isolated here, so moving to PostgreSQL later
means rewriting this one module.

Security notes (interview talking points)
  * Every query is parameterised; user input is never concatenated into SQL.
  * ORDER BY columns come from a fixed allowlist, because column names cannot
    be parameterised.
  * LIKE input is escaped so '%' and '_' typed by a user are treated literally.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from .detectors.base import Alert

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    mitre_id    TEXT    NOT NULL,
    mitre_name  TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    users       TEXT    NOT NULL,              -- JSON array
    start_ts    TEXT    NOT NULL,              -- ISO-8601 UTC, sorts lexicographically
    end_ts      TEXT    NOT NULL,
    count       INTEGER NOT NULL,
    description TEXT    NOT NULL,
    breached    INTEGER NOT NULL DEFAULT 0,
    status      TEXT    NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_alerts_start    ON alerts(start_ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ip       ON alerts(ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_type     ON alerts(type);

CREATE TABLE IF NOT EXISTS ingests (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       TEXT    NOT NULL,
    total    INTEGER NOT NULL,
    parsed   INTEGER NOT NULL,
    rejected INTEGER NOT NULL,
    alerts   INTEGER NOT NULL,
    seconds  REAL    NOT NULL
);
"""

STATUSES = ("open", "acknowledged", "resolved")

# API sort key -> SQL expression (allowlist)
SORT_COLUMNS = {
    "start": "start_ts",
    "count": "count",
    "type": "type",
    "severity": "CASE severity WHEN 'critical' THEN 2 ELSE 1 END",
}

TIMELINE_BUCKETS = {"hour": 13, "day": 10}   # chars of the ISO timestamp to keep


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def _row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "type": row["type"],
        "severity": row["severity"],
        "mitre_id": row["mitre_id"],
        "mitre_name": row["mitre_name"],
        "ip": row["ip"],
        "users": json.loads(row["users"]),
        "start": row["start_ts"],
        "end": row["end_ts"],
        "count": row["count"],
        "description": row["description"],
        "breached": bool(row["breached"]),
        "status": row["status"],
    }


def insert_alerts(conn: sqlite3.Connection, alerts: Iterable[Alert], replace: bool = True) -> int:
    """Store alerts. With replace=True the previous alerts are cleared first
    (one ingest = one consistent snapshot) inside a single transaction."""
    rows = [
        (a.type, a.severity, a.mitre_id, a.mitre_name, a.ip, json.dumps(list(a.users)),
         _iso(a.start), _iso(a.end), a.count, a.description, int(a.breached))
        for a in alerts
    ]
    with conn:   # commits on success, rolls back on error
        if replace:
            conn.execute("DELETE FROM alerts")
        conn.executemany(
            "INSERT INTO alerts (type, severity, mitre_id, mitre_name, ip, users, start_ts, end_ts,"
            " count, description, breached) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


def record_ingest(conn: sqlite3.Connection, total: int, parsed: int, rejected: int,
                  alerts: int, seconds: float) -> None:
    with conn:
        conn.execute(
            "INSERT INTO ingests (at, total, parsed, rejected, alerts, seconds) VALUES (?,?,?,?,?,?)",
            (_iso(datetime.now(timezone.utc)), total, parsed, rejected, alerts, seconds),
        )


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_alerts(conn: sqlite3.Connection, *, severity: Optional[str] = None, type: Optional[str] = None,
                status: Optional[str] = None, ip: Optional[str] = None, since: Optional[str] = None,
                until: Optional[str] = None, sort: str = "start", order: str = "desc",
                limit: int = 50, offset: int = 0) -> tuple[int, list[dict]]:
    where, params = [], []
    if severity:
        where.append("severity = ?"); params.append(severity)
    if type:
        where.append("type = ?"); params.append(type)
    if status:
        where.append("status = ?"); params.append(status)
    if ip:
        where.append("ip LIKE ? ESCAPE '\\'"); params.append(_escape_like(ip) + "%")   # prefix match
    if since:
        where.append("start_ts >= ?"); params.append(since)
    if until:
        where.append("start_ts <= ?"); params.append(until)
    clause = ("WHERE " + " AND ".join(where)) if where else ""

    sort_sql = SORT_COLUMNS.get(sort, SORT_COLUMNS["start"])      # allowlist, never raw input
    order_sql = "ASC" if order == "asc" else "DESC"

    total = conn.execute(f"SELECT COUNT(*) FROM alerts {clause}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM alerts {clause} ORDER BY {sort_sql} {order_sql}, id DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    return total, [_row_to_dict(r) for r in rows]


def get_alert(conn: sqlite3.Connection, alert_id: int) -> Optional[dict]:
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_dict(row) if row else None


def set_status(conn: sqlite3.Connection, alert_id: int, status: str) -> Optional[dict]:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    with conn:
        cur = conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    return get_alert(conn, alert_id) if cur.rowcount else None


def _group_counts(conn: sqlite3.Connection, column: str) -> dict:
    # `column` is an internal constant, never user input
    return {r[0]: r[1] for r in conn.execute(f"SELECT {column}, COUNT(*) FROM alerts GROUP BY {column}")}


def stats(conn: sqlite3.Connection, top_n: int = 8) -> dict:
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    breached = conn.execute("SELECT COUNT(*) FROM alerts WHERE breached = 1").fetchone()[0]

    # Top offenders ranked by failed attempts; impossible-travel alerts have no attempt volume.
    top = conn.execute(
        "SELECT ip, SUM(count) AS attempts, COUNT(*) AS alerts, MAX(breached) AS breached,"
        " group_concat(DISTINCT type) AS types FROM alerts"
        " WHERE type IN ('brute_force', 'credential_stuffing', 'anomalous_activity')"
        " GROUP BY ip ORDER BY attempts DESC, ip LIMIT ?", (top_n,)
    ).fetchall()

    last = conn.execute("SELECT * FROM ingests ORDER BY id DESC LIMIT 1").fetchone()
    return {
        "total": total,
        "breached": breached,
        "by_type": _group_counts(conn, "type"),
        "by_severity": _group_counts(conn, "severity"),
        "by_status": _group_counts(conn, "status"),
        "top_ips": [
            {"ip": r["ip"], "attempts": r["attempts"], "alerts": r["alerts"],
             "breached": bool(r["breached"]), "types": r["types"].split(",")}
            for r in top
        ],
        "last_ingest": dict(last) if last else None,
    }


def timeline(conn: sqlite3.Connection, bucket: str = "day") -> list[dict]:
    width = TIMELINE_BUCKETS.get(bucket, TIMELINE_BUCKETS["day"])
    rows = conn.execute(
        f"SELECT substr(start_ts, 1, {int(width)}) AS bucket, type, COUNT(*) AS n"
        " FROM alerts GROUP BY bucket, type ORDER BY bucket"
    ).fetchall()
    return [{"bucket": r["bucket"], "type": r["type"], "count": r["n"]} for r in rows]
