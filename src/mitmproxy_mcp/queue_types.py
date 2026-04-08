from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class HttpLogEntry:
    """Queued item representing a captured HTTP request/response pair."""

    req_method: str
    req_scheme: str
    req_host: str
    req_port: int
    req_path: str
    req_http_version: str
    req_headers: dict
    req_body: bytes | None
    req_timestamp_ms: float

    resp_status_code: int | None = None
    resp_reason: str | None = None
    resp_http_version: str | None = None
    resp_headers: dict | None = None
    resp_body: bytes | None = None
    resp_timestamp_ms: float | None = None

    duration_ms: float | None = None
    error_message: str | None = None


@dataclass(slots=True)
class WsLogEntry:
    """Queued item representing a captured WebSocket message."""

    http_log_id: int | None
    direction: str  # CLIENT_TO_SERVER or SERVER_TO_CLIENT
    payload: bytes
    is_text: bool
    timestamp_ms: float
