from __future__ import annotations

import asyncio
import logging
import re
import time
from queue import Full

from mitmproxy import http

from .app_state import AppState, InterceptedFlow
from .queue_types import HttpLogEntry, WsLogEntry

logger = logging.getLogger(__name__)


class LoggingAddon:
    """mitmproxy addon that captures HTTP and WebSocket traffic."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    # ------------------------------------------------------------------
    # HTTP hooks
    # ------------------------------------------------------------------

    async def request(self, flow: http.HTTPFlow) -> None:
        # Always record timestamp for duration calculation
        flow.metadata["req_ts"] = flow.request.timestamp_start

        if not self.state.logging_active.is_set():
            return

        # Interception logic
        if self.state.intercept_active.is_set() and self._matches_rules(flow):
            event = asyncio.Event()
            intercepted = InterceptedFlow(
                flow=flow,
                event=event,
                enqueued_at=time.time(),
            )
            self.state.intercept_queue[flow.id] = intercepted
            logger.info(
                "Intercepted: %s %s%s",
                flow.request.method,
                flow.request.host,
                flow.request.path,
            )

            try:
                await asyncio.wait_for(
                    event.wait(),
                    timeout=self.state.intercept_timeout_s,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Intercept timeout for flow %s, forwarding unmodified", flow.id
                )
            finally:
                self.state.intercept_queue.pop(flow.id, None)

    def response(self, flow: http.HTTPFlow) -> None:
        if not self.state.logging_active.is_set():
            return

        entry = self._build_http_entry(flow)
        self._enqueue(entry)

    def error(self, flow: http.HTTPFlow) -> None:
        if not self.state.logging_active.is_set():
            return

        entry = self._build_http_entry(flow, error=True)
        self._enqueue(entry)

    # ------------------------------------------------------------------
    # WebSocket hooks
    # ------------------------------------------------------------------

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if not self.state.logging_active.is_set():
            return

        if not flow.websocket or not flow.websocket.messages:
            return

        msg = flow.websocket.messages[-1]
        http_log_id = self.state.flow_to_log_id.get(flow.id)

        entry = WsLogEntry(
            http_log_id=http_log_id,
            direction="CLIENT_TO_SERVER" if msg.from_client else "SERVER_TO_CLIENT",
            payload=msg.content if isinstance(msg.content, bytes) else msg.content.encode("utf-8", errors="replace"),
            is_text=msg.is_text,
            timestamp_ms=msg.timestamp * 1000,
        )
        self._enqueue(entry)

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        self.state.flow_to_log_id.pop(flow.id, None)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_http_entry(self, flow: http.HTTPFlow, error: bool = False) -> HttpLogEntry:
        req = flow.request
        # Group duplicate headers into lists
        req_headers: dict[str, list[str]] = {}
        for k, v in req.headers.items(multi=True):
            req_headers.setdefault(k, []).append(v)

        resp_headers: dict[str, list[str]] | None = None
        resp_status = None
        resp_reason = None
        resp_http_version = None
        resp_body = None
        resp_timestamp_ms = None
        duration_ms = None
        error_message = None

        if flow.response and not error:
            resp = flow.response
            resp_headers = {}
            for k, v in resp.headers.items(multi=True):
                resp_headers.setdefault(k, []).append(v)
            resp_status = resp.status_code
            resp_reason = resp.reason
            resp_http_version = resp.http_version
            resp_body = resp.raw_content
            resp_timestamp_ms = resp.timestamp_end * 1000 if resp.timestamp_end else None
            req_ts = flow.metadata.get("req_ts", req.timestamp_start)
            if resp.timestamp_end and req_ts:
                duration_ms = (resp.timestamp_end - req_ts) * 1000

        if error and flow.error:
            error_message = flow.error.msg

        return HttpLogEntry(
            req_method=req.method,
            req_scheme=req.scheme,
            req_host=req.host,
            req_port=req.port,
            req_path=req.path,
            req_http_version=req.http_version,
            req_headers=req_headers,
            req_body=req.raw_content,
            req_timestamp_ms=req.timestamp_start * 1000 if req.timestamp_start else time.time() * 1000,
            resp_status_code=resp_status,
            resp_reason=resp_reason,
            resp_http_version=resp_http_version,
            resp_headers=resp_headers,
            resp_body=resp_body,
            resp_timestamp_ms=resp_timestamp_ms,
            duration_ms=duration_ms,
            error_message=error_message,
        )

    def _enqueue(self, entry: HttpLogEntry | WsLogEntry) -> None:
        try:
            self.state.queue.put(entry, block=True, timeout=0.05)
            self.state.enqueued_total += 1
        except Full:
            self.state.dropped_count += 1
            logger.warning("Queue full — dropped log entry")

    def _matches_rules(self, flow: http.HTTPFlow) -> bool:
        rules = self.state.intercept_rules
        if not rules:
            return True  # No rules = intercept everything

        for rule in rules:
            if not rule.enabled:
                continue
            method_ok = (not rule.methods) or (flow.request.method in rule.methods)
            host_ok = (not rule.host_pattern) or bool(
                re.search(rule.host_pattern, flow.request.host)
            )
            path_ok = (not rule.path_pattern) or bool(
                re.search(rule.path_pattern, flow.request.path)
            )
            if method_ok and host_ok and path_ok:
                return True
        return False
