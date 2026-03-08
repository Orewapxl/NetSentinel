from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .models import Alert, Event, IOC
from .utils import shannon_entropy


SEVERITY_SCORE = {
    "low": 20,
    "medium": 45,
    "high": 70,
    "critical": 90,
}


class RuleEngine:
    def __init__(self) -> None:
        self.portscan_window: dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)
        self.bruteforce_window: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
        self.dns_window: dict[str, deque[datetime]] = defaultdict(deque)

    def process(self, event: Event, ioc: IOC | None = None) -> list[Alert]:
        alerts: list[Alert] = []

        if ioc:
            alerts.append(self._ioc_alert(event, ioc))

        alerts.extend(self._detect_portscan(event))
        alerts.extend(self._detect_dns_abuse(event))
        alerts.extend(self._detect_bruteforce(event))
        return alerts

    def _ts(self, event: Event) -> datetime:
        ts = event.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts

    def _ioc_alert(self, event: Event, ioc: IOC) -> Alert:
        return Alert(
            rule_id="TI-001",
            title="Threat intelligence eşleşmesi",
            severity=ioc.severity,
            score=SEVERITY_SCORE[ioc.severity],
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            reason=f"IOC match: {ioc.value} ({ioc.source})",
            event=event.model_dump(mode="json"),
        )

    def _detect_portscan(self, event: Event) -> Iterable[Alert]:
        if not event.src_ip or not event.dst_port:
            return []
        if event.protocol and event.protocol.lower() not in {"tcp", "udp"}:
            return []

        now = self._ts(event)
        window = self.portscan_window[event.src_ip]
        window.append((now, event.dst_port))
        cutoff = now - timedelta(seconds=60)
        while window and window[0][0] < cutoff:
            window.popleft()

        unique_ports = {port for _, port in window}
        if len(unique_ports) >= 30:
            return [
                Alert(
                    rule_id="NET-PORTSCAN-001",
                    title="Port scan şüphesi",
                    severity="high",
                    score=75,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    reason=f"60 saniyede {len(unique_ports)} farklı porta erişim denendi.",
                    event=event.model_dump(mode="json"),
                )
            ]
        return []

    def _detect_dns_abuse(self, event: Event) -> Iterable[Alert]:
        if event.event_type != "dns_query" or not event.query or not event.src_ip:
            return []

        alerts: list[Alert] = []
        query = event.query.strip().lower().rstrip(".")
        entropy = shannon_entropy(query)
        now = self._ts(event)
        window = self.dns_window[event.src_ip]
        window.append(now)
        cutoff = now - timedelta(seconds=60)
        while window and window[0] < cutoff:
            window.popleft()

        if len(query) > 45 and entropy >= 4.0:
            alerts.append(
                Alert(
                    rule_id="DNS-001",
                    title="Yüksek entropy DNS sorgusu",
                    severity="medium",
                    score=50,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    reason=f"Şüpheli DNS query. entropy={entropy:.2f}, len={len(query)}",
                    event=event.model_dump(mode="json"),
                )
            )

        if len(window) >= 80:
            alerts.append(
                Alert(
                    rule_id="DNS-002",
                    title="Aşırı DNS sorgu yoğunluğu",
                    severity="high",
                    score=72,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    reason=f"60 saniyede {len(window)} DNS sorgusu gözlendi.",
                    event=event.model_dump(mode="json"),
                )
            )
        return alerts

    def _detect_bruteforce(self, event: Event) -> Iterable[Alert]:
        if event.event_type != "auth" or event.status != "failed":
            return []
        if not event.src_ip or not event.username:
            return []

        now = self._ts(event)
        key = (event.src_ip, event.username)
        window = self.bruteforce_window[key]
        window.append(now)
        cutoff = now - timedelta(minutes=5)
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= 7:
            return [
                Alert(
                    rule_id="AUTH-001",
                    title="Brute force şüphesi",
                    severity="high",
                    score=78,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    reason=f"5 dakikada kullanıcı {event.username} için {len(window)} başarısız giriş.",
                    event=event.model_dump(mode="json"),
                )
            ]
        return []
