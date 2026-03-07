from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Callable

from .models import Event


class LiveSniffer:
    def __init__(self, callback: Callable[[Event], None]):
        self.callback = callback
        self.stop_event = asyncio.Event()
        self.iface: str | None = None

    def _load_scapy(self):
        try:
            from scapy.all import DNS, DNSQR, IP, TCP, UDP, conf, get_if_list, sniff  # type: ignore
            return {
                "DNS": DNS,
                "DNSQR": DNSQR,
                "IP": IP,
                "TCP": TCP,
                "UDP": UDP,
                "conf": conf,
                "get_if_list": get_if_list,
                "sniff": sniff,
            }
        except Exception as e:
            raise RuntimeError(
                "Scapy başlatılamadı. Root/admin izni veya ortam uyumsuzluğu olabilir. "
                f"Detay: {e}"
            ) from e

    def resolve_iface(self, iface: str | None = None) -> str | None:
        if iface:
            return iface
        scapy = self._load_scapy()
        from .utils import choose_default_iface
        return choose_default_iface(scapy["get_if_list"]())

    def stop_filter(self, _pkt) -> bool:
        return self.stop_event.is_set()

    def parse_packet(self, pkt) -> Event | None:
        try:
            scapy = self._load_scapy()
            IP = scapy["IP"]
            TCP = scapy["TCP"]
            UDP = scapy["UDP"]
            DNS = scapy["DNS"]
            DNSQR = scapy["DNSQR"]

            src_ip = pkt[IP].src if pkt.haslayer(IP) else None
            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else None
            proto = None
            src_port = None
            dst_port = None
            event_type = "network"
            query = None
            hostname = None

            if pkt.haslayer(TCP):
                proto = "tcp"
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                proto = "udp"
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                event_type = "dns_query"
                query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            elif dst_port in (80, 443):
                hostname = dst_ip

            return Event(
                timestamp=datetime.utcnow(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                event_type=event_type,
                query=query,
                hostname=hostname,
                source="scapy",
                raw={},
            )
        except Exception:
            return None

    async def run(self, iface: str | None = None) -> None:
        scapy = self._load_scapy()
        resolved = self.resolve_iface(iface)
        if not resolved:
            raise RuntimeError("Uygun ağ arayüzü bulunamadı.")
        self.iface = resolved
        scapy["conf"].sniff_promisc = True

        loop = asyncio.get_running_loop()

        def _sniff() -> None:
            scapy["sniff"](
                iface=resolved,
                prn=lambda pkt: self._handle(pkt),
                store=False,
                stop_filter=self.stop_filter,
            )

        await loop.run_in_executor(None, _sniff)

    def _handle(self, pkt) -> None:
        event = self.parse_packet(pkt)
        if event:
            self.callback(event)
