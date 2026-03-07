import json
import random
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen

API = "http://127.0.0.1:8000/api/event"


def post(event: dict):
    data = json.dumps(event).encode()
    req = Request(API, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req) as resp:
        print(resp.read().decode())


if __name__ == "__main__":
    # Port scan simülasyonu
    src = "192.168.1.77"
    for port in range(1, 36):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src,
            "dst_ip": "10.0.0.10",
            "src_port": random.randint(30000, 65000),
            "dst_port": port,
            "protocol": "tcp",
            "event_type": "network",
            "source": "simulator",
        }
        post(event)
        time.sleep(0.1)

    # IOC domain simülasyonu
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "10.0.0.15",
        "dst_ip": "8.8.8.8",
        "src_port": 53000,
        "dst_port": 53,
        "protocol": "udp",
        "event_type": "dns_query",
        "query": "evil-c2.net",
        "source": "simulator",
    }
    post(event)
