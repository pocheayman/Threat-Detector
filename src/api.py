"""
FastAPI backend.

    uvicorn src.api:app --reload          # then open http://127.0.0.1:8000
    http://127.0.0.1:8000/docs            # auto-generated interactive API docs

Endpoints
    GET   /api/health              liveness + alert count
    POST  /api/ingest              body = raw log text; runs detectors, stores alerts
    GET   /api/alerts              filter, sort, paginate
    GET   /api/alerts/{id}         one alert
    PATCH /api/alerts/{id}         set status: open | acknowledged | resolved
    GET   /api/stats               totals, breakdowns, top offending IPs, last ingest
    GET   /api/timeline            alert counts per hour/day per attack type
    GET   /                        the dashboard
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import db
from .ingest import ingest_text, load_runtime

STATIC_DIR = Path(__file__).parent / "static"
DEFAULT_MAX_UPLOAD = 50 * 1024 * 1024        # 50 MB

Severity = Literal["high", "critical"]
AlertType = Literal["brute_force", "credential_stuffing", "impossible_travel", "anomalous_activity"]
Status = Literal["open", "acknowledged", "resolved"]
SortKey = Literal["start", "severity", "count", "type"]
Order = Literal["asc", "desc"]


class AlertOut(BaseModel):
    id: int
    type: str
    severity: str
    mitre_id: str
    mitre_name: str
    ip: str
    users: list[str]
    start: str
    end: str
    count: int
    description: str
    breached: bool
    status: str


class AlertPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AlertOut]


class StatusUpdate(BaseModel):
    status: Status


def create_app(db_path: Optional[str] = None, max_upload: Optional[int] = None) -> FastAPI:
    db_path = db_path or os.environ.get("THREAT_DB", "data/threat.db")
    max_upload = max_upload or int(os.environ.get("THREAT_MAX_UPLOAD", DEFAULT_MAX_UPLOAD))
    readonly = os.environ.get("THREAT_READONLY", "").lower() in ("1", "true", "yes")
    cfg, model = load_runtime()
    db.init_db(db_path)

    app = FastAPI(title="Threat Detector API", version="0.5.0",
                  description="Alerts from authentication-log analysis, mapped to MITRE ATT&CK.")

    def get_conn():
        conn = db.connect(db_path)          # one short-lived connection per request
        try:
            yield conn
        finally:
            conn.close()

    @app.get("/api/health")
    def health(conn=Depends(get_conn)):
        count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        return {"status": "ok", "alerts": count}

    @app.get("/api/config")
    def config():
        return {"readonly": readonly, "ml": model is not None, "trusted_networks": list(cfg.trusted_networks)}

    def forbid():
        if readonly:
            raise HTTPException(403, "This is a read-only demo. Run it locally to upload logs and triage alerts.")

    @app.post("/api/ingest")
    async def ingest(request: Request, replace: bool = True, conn=Depends(get_conn)):
        forbid()
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > max_upload:
            raise HTTPException(413, f"Log is larger than the {max_upload // (1024 * 1024)} MB limit")
        body = await request.body()
        if len(body) > max_upload:       # content-length can be absent or wrong
            raise HTTPException(413, f"Log is larger than the {max_upload // (1024 * 1024)} MB limit")
        text = body.decode("utf-8", errors="replace")
        result = await run_in_threadpool(ingest_text, conn, text, replace, cfg, model)
        if result["parsed"] == 0:
            raise HTTPException(422, "No valid log lines found. Expected lines like: "
                                     "2026-10-12T09:15:32Z auth user=alice ip=49.37.12.8 result=FAIL "
                                     "city=Mumbai lat=19.07 lon=72.88")
        return result

    @app.get("/api/alerts", response_model=AlertPage)
    def alerts(severity: Optional[Severity] = None, type: Optional[AlertType] = None,
               status: Optional[Status] = None,
               ip: Optional[str] = Query(None, max_length=45, description="IP prefix, e.g. 203.0.113."),
               since: Optional[str] = Query(None, max_length=30, description="ISO time, inclusive"),
               until: Optional[str] = Query(None, max_length=30, description="ISO time, inclusive"),
               sort: SortKey = "start", order: Order = "desc",
               limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
               conn=Depends(get_conn)):
        total, items = db.list_alerts(conn, severity=severity, type=type, status=status, ip=ip,
                                      since=since, until=until, sort=sort, order=order,
                                      limit=limit, offset=offset)
        return {"total": total, "limit": limit, "offset": offset, "items": items}

    @app.get("/api/alerts/{alert_id}", response_model=AlertOut)
    def alert(alert_id: int, conn=Depends(get_conn)):
        item = db.get_alert(conn, alert_id)
        if item is None:
            raise HTTPException(404, "Alert not found")
        return item

    @app.patch("/api/alerts/{alert_id}", response_model=AlertOut)
    def update_alert(alert_id: int, body: StatusUpdate, conn=Depends(get_conn)):
        forbid()
        item = db.set_status(conn, alert_id, body.status)
        if item is None:
            raise HTTPException(404, "Alert not found")
        return item

    @app.get("/api/stats")
    def stats(conn=Depends(get_conn)):
        return db.stats(conn)

    @app.get("/api/timeline")
    def timeline(bucket: Literal["hour", "day"] = "day", conn=Depends(get_conn)):
        return db.timeline(conn, bucket)

    # ---- dashboard ----
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(STATIC_DIR / "index.html")

    return app


app = create_app()
