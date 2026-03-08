from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import FastAPI, File, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .collector import LiveSniffer
from .config import APP_ENV, BASE_DIR, FORWARDED_ALLOW_IPS, PERSIST_RUNTIME, PROXY_HEADERS, ROOT_PATH, THREAT_INTEL_CSV, WEBSOCKET_CLIENT_LIMIT
from .detectors import RuleEngine
from .models import Event
from .store import RuntimeStore
from .threat_intel import ThreatIntel

app = FastAPI(title="NetSentinel", version="1.2.0", root_path=ROOT_PATH)
store = RuntimeStore()
intel = ThreatIntel()
engine = RuleEngine()
frontend_dir = BASE_DIR / "app" / "static"
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")


def schedule_event_processing(event: Event) -> None:
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(process_event(event))
    except RuntimeError:
        asyncio.run(process_event(event))


async def process_event(event: Event) -> None:
    await store.add_event(event)
    ioc = intel.match_event(event)
    alerts = engine.process(event, ioc)
    for alert in alerts:
        await store.add_alert(alert)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(frontend_dir / "index.html")


@app.get("/api/health")
async def health(request: Request) -> dict[str, Any]:
    return {
        "status": "ok",
        "environment": APP_ENV,
        "persist_runtime": PERSIST_RUNTIME,
        "threat_intel_file": str(THREAT_INTEL_CSV),
        "ip_ioc_count": len(intel.by_ip),
        "domain_ioc_count": len(intel.by_domain),
        "root_path": ROOT_PATH,
        "proxy_headers": PROXY_HEADERS,
        "forwarded_allow_ips": FORWARDED_ALLOW_IPS,
        "request_scheme": request.url.scheme,
        "request_host": request.headers.get("host", ""),
        "forwarded_proto": request.headers.get("x-forwarded-proto", ""),
    }


@app.get("/api/stats")
async def stats() -> dict[str, Any]:
    return await store.snapshot()


@app.post("/api/intel/reload")
async def reload_intel() -> dict[str, Any]:
    intel.reload()
    return {
        "ok": True,
        "ip_ioc_count": len(intel.by_ip),
        "domain_ioc_count": len(intel.by_domain),
    }


@app.post("/api/event")
async def ingest_event(event: Event) -> dict[str, Any]:
    await process_event(event)
    return {"ok": True}


@app.post("/api/ingest/jsonl")
async def ingest_jsonl(file: UploadFile = File(...)) -> dict[str, Any]:
    raw = await file.read()
    lines = raw.decode("utf-8", errors="ignore").splitlines()
    processed = 0
    errors = 0
    for line in lines:
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            event = Event(**data)
            await process_event(event)
            processed += 1
        except Exception:
            errors += 1
    return {"ok": True, "processed": processed, "errors": errors}


@app.post("/api/sniffer/start")
async def start_sniffer(iface: str | None = Query(default=None)) -> dict[str, Any]:
    if store.sniffer_task and not store.sniffer_task.done():
        return {"ok": True, "message": "Sniffer zaten çalışıyor."}

    sniffer = LiveSniffer(schedule_event_processing)
    stop_event = sniffer.stop_event

    async def runner() -> None:
        await sniffer.run(iface=iface)

    task = asyncio.create_task(runner())
    store.sniffer_task = task
    store.sniffer_stop = stop_event
    return {"ok": True, "message": "Sniffer başlatıldı.", "iface": sniffer.resolve_iface(iface)}


@app.post("/api/sniffer/stop")
async def stop_sniffer() -> dict[str, Any]:
    if not store.sniffer_task:
        return {"ok": True, "message": "Sniffer çalışmıyor."}
    if store.sniffer_stop:
        store.sniffer_stop.set()
    return {"ok": True, "message": "Sniffer durdurma sinyali gönderildi."}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    if len(store.ws_clients) >= WEBSOCKET_CLIENT_LIMIT:
        await ws.close(code=1013)
        return
    await ws.accept()
    store.ws_clients.add(ws)
    try:
        await ws.send_json({"type": "hello", "message": "connected"})
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        store.ws_clients.discard(ws)
    except Exception:
        store.ws_clients.discard(ws)


@app.get("/api/export/alerts")
async def export_alerts() -> list[dict[str, Any]]:
    snapshot = await store.snapshot()
    return snapshot["recent_alerts"]


@app.get("/api/export/events")
async def export_events(limit: int = 100) -> list[dict[str, Any]]:
    snapshot = await store.snapshot()
    return snapshot["recent_events"][:limit]
