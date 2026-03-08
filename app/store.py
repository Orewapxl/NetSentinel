from __future__ import annotations

import asyncio
import json
from collections import Counter, deque
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import MAX_ALERTS, MAX_EVENTS, PERSIST_RUNTIME, RUNTIME_DIR
from .models import Alert, Event


class RuntimeStore:
    def __init__(self) -> None:
        self.events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=MAX_ALERTS)
        self.counters = Counter()
        self.lock = asyncio.Lock()
        self.ws_clients: set[Any] = set()
        self.sniffer_task = None
        self.sniffer_stop = None
        self.runtime_file: Path = RUNTIME_DIR / "runtime_snapshot.json"
        self._load_runtime()

    def _load_runtime(self) -> None:
        if not PERSIST_RUNTIME or not self.runtime_file.exists():
            return
        try:
            data = json.loads(self.runtime_file.read_text(encoding="utf-8"))
            self.events.extend(data.get("recent_events", [])[:MAX_EVENTS])
            self.alerts.extend(data.get("recent_alerts", [])[:MAX_ALERTS])
            self.counters.update(data.get("counters", {}))
        except Exception:
            self.events.clear()
            self.alerts.clear()
            self.counters.clear()

    async def _persist_runtime(self) -> None:
        if not PERSIST_RUNTIME:
            return
        payload = {
            "saved_at": datetime.utcnow().isoformat() + "Z",
            "counters": dict(self.counters),
            "recent_events": list(self.events),
            "recent_alerts": list(self.alerts),
        }
        await asyncio.to_thread(
            self.runtime_file.write_text,
            json.dumps(payload, ensure_ascii=False, indent=2),
            "utf-8",
        )

    async def add_event(self, event: Event) -> None:
        async with self.lock:
            data = event.model_dump(mode="json")
            self.events.appendleft(data)
            self.counters["events_total"] += 1
            if event.protocol:
                self.counters[f"proto:{event.protocol.lower()}"] += 1
            if event.event_type:
                self.counters[f"etype:{event.event_type.lower()}"] += 1
        await self._persist_runtime()

    async def add_alert(self, alert: Alert) -> None:
        async with self.lock:
            data = alert.model_dump(mode="json")
            self.alerts.appendleft(data)
            self.counters["alerts_total"] += 1
            self.counters[f"severity:{alert.severity}"] += 1
        await self._persist_runtime()
        await self.broadcast({"type": "alert", "data": data})

    async def broadcast(self, message: dict[str, Any]) -> None:
        stale = []
        for ws in list(self.ws_clients):
            try:
                await ws.send_json(message)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.ws_clients.discard(ws)

    async def snapshot(self) -> dict[str, Any]:
        async with self.lock:
            proto = {k.split(":", 1)[1]: v for k, v in self.counters.items() if k.startswith("proto:")}
            etypes = {k.split(":", 1)[1]: v for k, v in self.counters.items() if k.startswith("etype:")}
            severities = {k.split(":", 1)[1]: v for k, v in self.counters.items() if k.startswith("severity:")}
            return {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "totals": {
                    "events": self.counters["events_total"],
                    "alerts": self.counters["alerts_total"],
                },
                "protocols": proto,
                "event_types": etypes,
                "severities": severities,
                "recent_events": list(self.events)[:50],
                "recent_alerts": list(self.alerts)[:50],
            }
