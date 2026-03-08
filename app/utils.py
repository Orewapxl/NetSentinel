import math
from collections import Counter
from typing import Iterable


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def choose_default_iface(candidates: Iterable[str]) -> str | None:
    for iface in candidates:
        name = iface.lower()
        if any(skip in name for skip in ("lo", "loopback", "npcap loopback")):
            continue
        return iface
    return None
