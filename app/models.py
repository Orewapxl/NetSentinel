from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]


class Event(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    event_type: str = "network"
    query: str | None = None
    hostname: str | None = None
    http_host: str | None = None
    http_uri: str | None = None
    action: str | None = None
    username: str | None = None
    status: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    source: str = "custom"
    raw: dict[str, Any] = Field(default_factory=dict)


class Alert(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    rule_id: str
    title: str
    severity: Severity
    score: int
    src_ip: str | None = None
    dst_ip: str | None = None
    ioc_value: str | None = None
    ioc_type: str | None = None
    reason: str
    event: dict[str, Any]


class IOC(BaseModel):
    type: Literal["ip", "domain"]
    value: str
    severity: Severity
    source: str
    note: str | None = None
