from __future__ import annotations

import csv
from pathlib import Path
from typing import Optional

from .config import THREAT_INTEL_CSV
from .models import Event, IOC


class ThreatIntel:
    def __init__(self, csv_path: Path = THREAT_INTEL_CSV):
        self.csv_path = csv_path
        self.by_ip: dict[str, IOC] = {}
        self.by_domain: dict[str, IOC] = {}
        self.reload()

    def reload(self) -> None:
        self.by_ip.clear()
        self.by_domain.clear()
        if not self.csv_path.exists():
            return
        with self.csv_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    ioc = IOC(**row)
                except Exception:
                    continue
                if ioc.type == "ip":
                    self.by_ip[ioc.value.strip()] = ioc
                elif ioc.type == "domain":
                    self.by_domain[ioc.value.strip().lower()] = ioc

    def match_event(self, event: Event) -> Optional[IOC]:
        for ip in (event.src_ip, event.dst_ip):
            if ip and ip in self.by_ip:
                return self.by_ip[ip]

        domains = [event.query, event.hostname, event.http_host]
        for domain in domains:
            if not domain:
                continue
            normalized = domain.strip().lower().rstrip(".")
            if normalized in self.by_domain:
                return self.by_domain[normalized]
            parts = normalized.split(".")
            for i in range(1, len(parts) - 1):
                suffix = ".".join(parts[i:])
                if suffix in self.by_domain:
                    return self.by_domain[suffix]
        return None
