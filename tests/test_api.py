import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src import db
from src.api import create_app

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def log_text(tmp_path_factory):
    out = tmp_path_factory.mktemp("gen")
    subprocess.run([sys.executable, str(ROOT / "src" / "generator.py"), "--out", str(out)],
                   check=True, capture_output=True)
    return (out / "auth.log").read_text()


@pytest.fixture()
def client(tmp_path):
    return TestClient(create_app(str(tmp_path / "t.db")))


@pytest.fixture()
def loaded(client, log_text):
    r = client.post("/api/ingest", content=log_text)
    assert r.status_code == 200
    return client


# ---------- health / ingest ----------

def test_health_empty_db(client):
    assert client.get("/api/health").json() == {"status": "ok", "alerts": 0}


def test_ingest_generated_log(client, log_text):
    r = client.post("/api/ingest", content=log_text)
    assert r.status_code == 200
    body = r.json()
    assert body["parsed"] == body["lines"] == 14500
    assert body["rejected"] == 0
    assert body["alerts"] == 18
    assert client.get("/api/health").json()["alerts"] == 18


def test_ingest_replaces_by_default_and_can_append(client, log_text):
    client.post("/api/ingest", content=log_text)
    client.post("/api/ingest", content=log_text)
    assert client.get("/api/health").json()["alerts"] == 18            # replaced
    client.post("/api/ingest?replace=false", content=log_text)
    assert client.get("/api/health").json()["alerts"] == 36            # appended


def test_ingest_garbage_is_rejected_with_helpful_message(client):
    r = client.post("/api/ingest", content="this is not a log\nneither is this\n")
    assert r.status_code == 422
    assert "Expected lines like" in r.json()["detail"]


def test_ingest_empty_body_is_rejected(client):
    assert client.post("/api/ingest", content="").status_code == 422


def test_ingest_skips_bad_lines_but_keeps_good_ones(client, log_text):
    mixed = "garbage\n" + log_text + "\n\xff\xfe\n"
    body = client.post("/api/ingest", content=mixed.encode("utf-8", errors="surrogateescape")).json()
    assert body["parsed"] == 14500 and body["rejected"] >= 1


def test_upload_size_limit(tmp_path, log_text):
    small = TestClient(create_app(str(tmp_path / "s.db"), max_upload=1000))
    assert small.post("/api/ingest", content=log_text).status_code == 413


# ---------- alerts: list / filter / sort / paginate ----------

def test_list_alerts_defaults(loaded):
    j = loaded.get("/api/alerts").json()
    assert j["total"] == 18 and j["limit"] == 50 and j["offset"] == 0
    assert len(j["items"]) == 18
    starts = [a["start"] for a in j["items"]]
    assert starts == sorted(starts, reverse=True)                      # newest first


def test_filter_by_severity_and_type(loaded):
    crit = loaded.get("/api/alerts?severity=critical").json()
    assert crit["total"] == 4 and all(a["severity"] == "critical" for a in crit["items"])
    stuff = loaded.get("/api/alerts?type=credential_stuffing").json()
    assert stuff["total"] == 4 and all(a["type"] == "credential_stuffing" for a in stuff["items"])
    both = loaded.get("/api/alerts?severity=critical&type=credential_stuffing").json()
    assert both["total"] == 0


def test_filter_by_ip_prefix(loaded):
    ip = loaded.get("/api/alerts?type=brute_force").json()["items"][0]["ip"]
    prefix = ip.rsplit(".", 1)[0] + "."
    hits = loaded.get("/api/alerts", params={"ip": prefix}).json()
    assert hits["total"] >= 1 and all(a["ip"].startswith(prefix) for a in hits["items"])


def test_like_wildcards_are_treated_literally(loaded):
    # '%' would match everything if it were not escaped
    assert loaded.get("/api/alerts", params={"ip": "%"}).json()["total"] == 0
    assert loaded.get("/api/alerts", params={"ip": "_"}).json()["total"] == 0


def test_sql_injection_attempts_are_inert(loaded):
    for payload in ["' OR 1=1 --", "1.1.1.1'; DROP TABLE alerts; --"]:
        assert loaded.get("/api/alerts", params={"ip": payload}).json()["total"] == 0
    assert loaded.get("/api/health").json()["alerts"] == 18            # table still there


def test_sort_by_attempts_and_severity(loaded):
    by_count = loaded.get("/api/alerts?sort=count&order=desc").json()["items"]
    counts = [a["count"] for a in by_count]
    assert counts == sorted(counts, reverse=True)
    by_sev = loaded.get("/api/alerts?sort=severity&order=desc").json()["items"]
    assert by_sev[0]["severity"] == "critical" and by_sev[-1]["severity"] == "high"


def test_invalid_sort_filter_values_are_rejected(loaded):
    assert loaded.get("/api/alerts?sort=evil;drop").status_code == 422
    assert loaded.get("/api/alerts?severity=low").status_code == 422
    assert loaded.get("/api/alerts?limit=0").status_code == 422
    assert loaded.get("/api/alerts?limit=501").status_code == 422
    assert loaded.get("/api/alerts?offset=-1").status_code == 422


def test_pagination_covers_every_alert_once(loaded):
    seen = []
    for offset in range(0, 18, 5):
        page = loaded.get(f"/api/alerts?limit=5&offset={offset}").json()
        assert page["total"] == 18
        seen += [a["id"] for a in page["items"]]
    assert len(seen) == 18 == len(set(seen))
    assert loaded.get("/api/alerts?limit=5&offset=100").json()["items"] == []


def test_time_range_filter(loaded):
    everything = loaded.get("/api/alerts").json()["items"]
    cut = sorted(a["start"] for a in everything)[9]
    later = loaded.get("/api/alerts", params={"since": cut}).json()
    earlier = loaded.get("/api/alerts", params={"until": cut}).json()
    assert 0 < later["total"] < 18 and 0 < earlier["total"] < 18


# ---------- single alert / status ----------

def test_get_alert_and_404(loaded):
    first = loaded.get("/api/alerts").json()["items"][0]
    one = loaded.get(f"/api/alerts/{first['id']}").json()
    assert one == first
    assert loaded.get("/api/alerts/999999").status_code == 404


def test_update_status_roundtrip(loaded):
    aid = loaded.get("/api/alerts").json()["items"][0]["id"]
    r = loaded.patch(f"/api/alerts/{aid}", json={"status": "acknowledged"})
    assert r.status_code == 200 and r.json()["status"] == "acknowledged"
    assert loaded.get(f"/api/alerts/{aid}").json()["status"] == "acknowledged"
    assert loaded.get("/api/alerts?status=acknowledged").json()["total"] == 1
    assert loaded.get("/api/stats").json()["by_status"]["acknowledged"] == 1


def test_update_status_validation(loaded):
    aid = loaded.get("/api/alerts").json()["items"][0]["id"]
    assert loaded.patch(f"/api/alerts/{aid}", json={"status": "deleted"}).status_code == 422
    assert loaded.patch(f"/api/alerts/{aid}", json={}).status_code == 422
    assert loaded.patch("/api/alerts/999999", json={"status": "open"}).status_code == 404


# ---------- stats / timeline ----------

def test_stats_shape_and_consistency(loaded):
    s = loaded.get("/api/stats").json()
    assert s["total"] == 18
    assert sum(s["by_type"].values()) == 18
    assert sum(s["by_severity"].values()) == 18
    assert s["by_type"]["brute_force"] == 5 and s["by_type"]["credential_stuffing"] == 4
    assert s["last_ingest"]["parsed"] == 14500
    ranked = [o["attempts"] for o in s["top_ips"]]
    assert ranked == sorted(ranked, reverse=True) and len(ranked) <= 8


def test_stats_on_empty_db(client):
    s = client.get("/api/stats").json()
    assert s["total"] == 0 and s["top_ips"] == [] and s["last_ingest"] is None


def test_timeline_counts_add_up(loaded):
    for bucket, width in (("day", 10), ("hour", 13)):
        rows = loaded.get(f"/api/timeline?bucket={bucket}").json()
        assert sum(r["count"] for r in rows) == 18
        assert all(len(r["bucket"]) == width for r in rows)
    assert loaded.get("/api/timeline?bucket=year").status_code == 422


# ---------- dashboard / static ----------

def test_dashboard_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "Threat Detector" in r.text


def test_chartjs_is_served_locally(client):
    r = client.get("/static/vendor/chart.umd.js")
    assert r.status_code == 200 and len(r.content) > 100_000


# ---------- hostile log content ----------

def test_attacker_controlled_strings_are_stored_verbatim_not_executed(client):
    """Usernames come from the log, so they can hold HTML. The API must return them
    as plain JSON data; the dashboard builds its DOM with textContent."""
    xss = "<b>bold</b><script>alert(1)</script>"
    lines = [f"2026-10-01T10:00:{i:02d}Z auth user={xss} ip=203.0.113.9 result=FAIL city=Mumbai lat=19.07 lon=72.88"
             for i in range(15)]
    assert client.post("/api/ingest", content="\n".join(lines)).status_code == 200
    item = client.get("/api/alerts").json()["items"][0]
    assert item["users"] == [xss]
    assert client.headers.get("content-type", "") != "text/html"


# ---------- db layer directly ----------

def test_db_set_status_rejects_unknown_value(tmp_path):
    path = tmp_path / "x.db"
    db.init_db(path)
    conn = db.connect(path)
    with pytest.raises(ValueError):
        db.set_status(conn, 1, "bogus")
    conn.close()
