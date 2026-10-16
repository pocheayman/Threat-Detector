import pytest
from fastapi.testclient import TestClient

from src.detectors import DetectorConfig, run_all
from src.detectors.base import is_trusted
from src.evaluate import evaluate
from src.generator import OFFICE_NETWORK, generate
from src.ingest import load_runtime
from src.ml import ALL_FEATURES, AnomalyModel, build_features, train_model
from src.ml.train import simulated_baseline
from src.parser import parse_lines, to_dataframe
from src.pipeline import detect, merge_hybrid

HARD = dict(slow_brute=4, slow_stuffing=3, nat_bursts=3, vpn_users=3)


def frame(data):
    return to_dataframe(list(parse_lines(data["lines"])))


@pytest.fixture(scope="module")
def model():
    return train_model(simulated_baseline(days=14), trusted_networks=(OFFICE_NETWORK,))


@pytest.fixture(scope="module")
def hard():
    d = generate(seed=3, **HARD)
    return d, frame(d)


def test_generator_default_unchanged_by_hard_options():
    assert generate(seed=5)["lines"] == generate(seed=5, slow_brute=0, nat_bursts=0)["lines"]


def test_hard_generator_has_slow_attacks_and_benign_scenarios(hard):
    d, _ = hard
    assert sum(1 for t in d["truth"] if t.get("slow")) == 7
    assert {b["type"] for b in d["benign"]} == {"benign_nat_burst", "benign_vpn"}


def test_features_one_row_per_ip_hour(hard):
    _, df = hard
    f = build_features(df)
    assert not f.duplicated(["ip", "hour"]).any()
    assert set(ALL_FEATURES) <= set(f.columns)
    assert (f["fails"] + f["successes"] == f["events"]).all()


def test_features_empty_frame():
    assert build_features(to_dataframe([])).empty


def test_rules_miss_slow_attacks(hard):
    d, df = hard
    r = evaluate(run_all(df, DetectorConfig()), d["truth"], benign=d["benign"])
    assert r["variants"]["slow"]["detected"] == 0


def test_model_catches_slow_attacks_without_false_alarms(hard, model):
    d, df = hard
    cfg = DetectorConfig(trusted_networks=(OFFICE_NETWORK,))
    r = evaluate(model.detect(df, cfg), d["truth"], benign=d["benign"])
    assert r["variants"]["slow"]["detected"] == r["variants"]["slow"]["attacks"]
    assert r["overall"]["false_positives"] == 0


def test_ml_alerts_explain_themselves(hard, model):
    _, df = hard
    alerts = model.detect(df, DetectorConfig(trusted_networks=(OFFICE_NETWORK,)))
    assert alerts and all(a.type == "anomalous_activity" and a.mitre_id == "T1110" for a in alerts)
    assert all("typical" in a.description or "accounts" in a.description for a in alerts)


def test_trusted_network_is_skipped(hard, model):
    d, df = hard
    nat_ips = {b["ip"] for b in d["benign"] if b["type"] == "benign_nat_burst"}
    alerts = run_all(df, DetectorConfig(trusted_networks=(OFFICE_NETWORK,)))
    assert not nat_ips & {a.ip for a in alerts}
    assert is_trusted("115.249.3.4", (OFFICE_NETWORK,)) and not is_trusted("8.8.8.8", (OFFICE_NETWORK,))


def test_hybrid_has_full_recall_and_no_duplicates(hard, model):
    d, df = hard
    cfg = DetectorConfig(trusted_networks=(OFFICE_NETWORK,))
    alerts = detect(df, cfg, model)
    assert evaluate(alerts, d["truth"], benign=d["benign"])["overall"]["recall"] == 1
    rules = run_all(df, cfg)
    ml = model.detect(df, cfg)
    assert len(merge_hybrid(rules, ml)) <= len(rules) + len(ml)


def test_model_save_load_roundtrip(hard, model, tmp_path):
    _, df = hard
    model.save(tmp_path / "m.joblib")
    again = AnomalyModel.load(tmp_path / "m.joblib")
    assert len(again.detect(df)) == len(model.detect(df))


def test_load_refuses_foreign_object(tmp_path):
    import joblib
    joblib.dump({"x": 1}, tmp_path / "bad.joblib")
    with pytest.raises(ValueError):
        AnomalyModel.load(tmp_path / "bad.joblib")


def test_training_needs_history():
    with pytest.raises(ValueError):
        train_model(to_dataframe([]))


def test_load_runtime_from_env(monkeypatch, tmp_path, model):
    model.save(tmp_path / "m.joblib")
    monkeypatch.setenv("THREAT_MODEL", str(tmp_path / "m.joblib"))
    monkeypatch.setenv("THREAT_TRUSTED_NETWORKS", "10.0.0.0/8, 192.168.0.0/16")
    cfg, m = load_runtime()
    assert m is not None and cfg.trusted_networks == ("10.0.0.0/8", "192.168.0.0/16")


def _client(tmp_path, monkeypatch, **env):
    from src.api import create_app
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return TestClient(create_app(str(tmp_path / "t.db")))


def test_api_ml_alerts_and_type_filter(tmp_path, monkeypatch, model, hard):
    model.save(tmp_path / "m.joblib")
    c = _client(tmp_path, monkeypatch, THREAT_MODEL=str(tmp_path / "m.joblib"),
                THREAT_TRUSTED_NETWORKS=OFFICE_NETWORK)
    assert c.get("/api/config").json()["ml"] is True
    assert c.post("/api/ingest", content="\n".join(hard[0]["lines"])).status_code == 200
    r = c.get("/api/alerts", params={"type": "anomalous_activity"}).json()
    assert r["total"] > 0 and all(a["type"] == "anomalous_activity" for a in r["items"])
    assert c.get("/api/stats").json()["by_type"]["anomalous_activity"] == r["total"]


def test_readonly_demo_blocks_writes_but_allows_reads(tmp_path, monkeypatch, hard):
    c = _client(tmp_path, monkeypatch, THREAT_READONLY="1", THREAT_MODEL=str(tmp_path / "none"))
    assert c.get("/api/config").json()["readonly"] is True
    assert c.post("/api/ingest", content="x").status_code == 403
    assert c.patch("/api/alerts/1", json={"status": "resolved"}).status_code == 403
    assert c.get("/api/alerts").status_code == 200
