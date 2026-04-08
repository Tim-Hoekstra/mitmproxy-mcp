from __future__ import annotations

import asyncio
import base64
import json
import logging
import secrets
import string
import time
import urllib.parse
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .app_state import AppState, InterceptRule
from .db import (
    get_http_log_by_id,
    get_http_logs,
    get_http_logs_by_ids,
    get_http_logs_regex,
    get_ws_logs,
    get_ws_logs_regex,
    health_check,
    insert_config_snapshot,
    insert_http_log,
    update_note,
)
from .json_utils import extract_json_path, smart_body_content
from .protection import analyze_protection_for_log
from .queue_types import HttpLogEntry

logger = logging.getLogger(__name__)

server = Server("mitmproxy-mcp")


def _json_result(data: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, default=str))]


def _error(msg: str) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps({"error": msg}))]


# Will be set by main.py before the server starts
_state: AppState | None = None


def set_state(state: AppState) -> None:
    global _state
    _state = state


def _get_state() -> AppState:
    assert _state is not None, "AppState not initialised"
    return _state


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # 1. HTTP Request
        Tool(
            name="send_http_request",
            description="Send an HTTP request through the mitmproxy proxy and return the full response with log_id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "method": {"type": "string", "description": "HTTP method"},
                    "url": {"type": "string", "description": "Full URL including scheme"},
                    "headers": {"type": "object", "description": "Request headers", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string", "description": "Request body (UTF-8)"},
                    "body_base64": {"type": "string", "description": "Request body (base64, takes precedence over body)"},
                    "timeout_seconds": {"type": "number", "description": "Request timeout", "default": 30},
                },
                "required": ["method", "url"],
            },
        ),
        # 2. Proxy History
        Tool(
            name="get_proxy_http_history",
            description="Return a paginated list of logged HTTP requests and responses (newest-first, no bodies).",
            inputSchema={
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Entries to return (max 200)", "default": 20},
                    "offset": {"type": "integer", "description": "Entries to skip", "default": 0},
                },
            },
        ),
        Tool(
            name="get_proxy_http_history_regex",
            description="Regex search across HTTP history (URL, headers, bodies).",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "POSIX regex pattern"},
                    "search_fields": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["url", "req_headers", "resp_headers", "req_body", "resp_body"]},
                        "description": "Fields to search (default: all)",
                    },
                    "count": {"type": "integer", "default": 20},
                    "offset": {"type": "integer", "default": 0},
                },
                "required": ["pattern"],
            },
        ),
        Tool(
            name="get_proxy_websocket_history",
            description="Return a paginated list of WebSocket messages.",
            inputSchema={
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "default": 50},
                    "offset": {"type": "integer", "default": 0},
                    "http_log_id": {"type": "integer", "description": "Filter to one WS connection"},
                },
            },
        ),
        Tool(
            name="get_proxy_websocket_history_regex",
            description="Regex filter over WebSocket payload content.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "direction": {"type": "string", "enum": ["CLIENT_TO_SERVER", "SERVER_TO_CLIENT"]},
                    "count": {"type": "integer", "default": 50},
                    "offset": {"type": "integer", "default": 0},
                },
                "required": ["pattern"],
            },
        ),
        Tool(
            name="get_flow_details",
            description="Retrieve full request/response detail for log entries with smart content truncation. Large JSON bodies are returned as structure previews — use extract_json_fields to drill in.",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_ids": {"type": "array", "items": {"type": "integer"}, "description": "Up to 10 IDs"},
                    "include_content": {"type": "boolean", "default": True},
                    "truncate_at": {"type": "integer", "default": 2000, "description": "Byte threshold for truncation"},
                },
                "required": ["log_ids"],
            },
        ),
        # 3. Interception
        Tool(
            name="set_intercept_rules",
            description="Configure which requests are held for inspection. Empty rules = intercept all. Does not enable interception — use set_proxy_intercept_state.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rules": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "methods": {"type": "array", "items": {"type": "string"}},
                                "host_pattern": {"type": "string"},
                                "path_pattern": {"type": "string"},
                                "enabled": {"type": "boolean", "default": True},
                            },
                        },
                    },
                },
                "required": ["rules"],
            },
        ),
        Tool(
            name="get_intercepted_requests",
            description="List all requests currently held in the intercept queue waiting for forward/drop decision.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="forward_request",
            description="Release a held intercepted request, optionally with modifications to method, URL, headers, or body.",
            inputSchema={
                "type": "object",
                "properties": {
                    "flow_id": {"type": "string"},
                    "modify_headers": {"type": "object", "description": "Headers to add/override (null value removes)", "additionalProperties": {}},
                    "modify_body": {"type": "string"},
                    "modify_body_base64": {"type": "string"},
                    "modify_url": {"type": "string"},
                    "modify_method": {"type": "string"},
                },
                "required": ["flow_id"],
            },
        ),
        Tool(
            name="drop_request",
            description="Kill a held intercepted request. Client receives a connection error.",
            inputSchema={
                "type": "object",
                "properties": {
                    "flow_id": {"type": "string"},
                    "reason": {"type": "string", "description": "Reason stored in error_message"},
                },
                "required": ["flow_id"],
            },
        ),
        # 4. Proxy Control
        Tool(
            name="set_proxy_intercept_state",
            description="Toggle logging and/or interception independently.",
            inputSchema={
                "type": "object",
                "properties": {
                    "logging": {"type": "boolean", "description": "Enable/disable traffic logging to DB"},
                    "intercept": {"type": "boolean", "description": "Enable/disable request interception"},
                },
            },
        ),
        Tool(
            name="get_proxy_status",
            description="Health snapshot: proxy thread, queue depth, dropped count, DB status, uptime.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="replay_request",
            description="Re-send a logged request by ID through the proxy, optionally modified. Returns new log_id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_id": {"type": "integer"},
                    "modify_headers": {"type": "object", "additionalProperties": {}},
                    "modify_body": {"type": "string"},
                    "modify_body_base64": {"type": "string"},
                    "modify_url": {"type": "string"},
                    "modify_method": {"type": "string"},
                },
                "required": ["log_id"],
            },
        ),
        # 5. Analysis
        Tool(
            name="extract_json_fields",
            description="Extract specific fields from a request/response JSON body using JSONPath (e.g. $.data.users[0].id).",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_id": {"type": "integer"},
                    "content_type": {"type": "string", "enum": ["request", "response"]},
                    "json_paths": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["log_id", "content_type", "json_paths"],
            },
        ),
        Tool(
            name="analyze_protection",
            description="Analyse a response for bot protection/WAF mechanisms. Detects Cloudflare, Akamai, PerimeterX, DataDome, reCAPTCHA, hCaptcha with confidence scores and remediation.",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_id": {"type": "integer"},
                    "extract_scripts": {"type": "boolean", "default": True},
                },
                "required": ["log_id"],
            },
        ),
        # 6. Annotation
        Tool(
            name="add_log_note",
            description="Attach a text annotation to an http_logs or ws_logs row.",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_id": {"type": "integer"},
                    "note": {"type": "string", "description": "Max 4000 chars"},
                    "log_type": {"type": "string", "enum": ["http", "websocket"], "default": "http"},
                },
                "required": ["log_id", "note"],
            },
        ),
        # 7. Raw Wire Format
        Tool(
            name="get_raw_http_message",
            description="Return a logged HTTP entry as raw wire-format strings for request and/or response.",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_id": {"type": "integer"},
                    "include": {"type": "string", "enum": ["request", "response", "both"], "default": "both"},
                    "body_encoding": {"type": "string", "enum": ["auto", "base64", "utf8", "omit"], "default": "auto"},
                },
                "required": ["log_id"],
            },
        ),
        # 8. Configuration
        Tool(
            name="get_config",
            description="Return current proxy configuration.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="set_config",
            description="Update proxy configuration (logging_enabled, label). Persists to config_snapshots.",
            inputSchema={
                "type": "object",
                "properties": {
                    "logging_enabled": {"type": "boolean"},
                    "label": {"type": "string"},
                },
            },
        ),
        # 9. Encoding / Utility
        Tool(
            name="url_encode",
            description="Percent-encode a string for use in a URL.",
            inputSchema={
                "type": "object",
                "properties": {
                    "value": {"type": "string"},
                    "safe": {"type": "string", "default": ""},
                },
                "required": ["value"],
            },
        ),
        Tool(
            name="url_decode",
            description="Decode a percent-encoded URL string.",
            inputSchema={"type": "object", "properties": {"value": {"type": "string"}}, "required": ["value"]},
        ),
        Tool(
            name="base64_encode",
            description="Base64-encode a string.",
            inputSchema={
                "type": "object",
                "properties": {
                    "value": {"type": "string"},
                    "url_safe": {"type": "boolean", "default": False},
                },
                "required": ["value"],
            },
        ),
        Tool(
            name="base64_decode",
            description="Decode a base64-encoded string.",
            inputSchema={
                "type": "object",
                "properties": {
                    "value": {"type": "string"},
                    "url_safe": {"type": "boolean", "default": False},
                    "as_text": {"type": "boolean", "default": True},
                },
                "required": ["value"],
            },
        ),
        Tool(
            name="generate_random_string",
            description="Generate a cryptographically random string.",
            inputSchema={
                "type": "object",
                "properties": {
                    "length": {"type": "integer", "description": "Max 4096"},
                    "charset": {"type": "string", "default": "alphanumeric", "description": "alphanumeric, alpha, numeric, hex, base64, printable, or custom chars"},
                },
                "required": ["length"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    state = _get_state()

    try:
        if name == "send_http_request":
            return await _send_http_request(state, arguments)
        elif name == "get_proxy_http_history":
            return _get_proxy_http_history(state, arguments)
        elif name == "get_proxy_http_history_regex":
            return _get_proxy_http_history_regex(state, arguments)
        elif name == "get_proxy_websocket_history":
            return _get_proxy_websocket_history(state, arguments)
        elif name == "get_proxy_websocket_history_regex":
            return _get_proxy_websocket_history_regex(state, arguments)
        elif name == "get_flow_details":
            return _get_flow_details(state, arguments)
        elif name == "set_intercept_rules":
            return _set_intercept_rules(state, arguments)
        elif name == "get_intercepted_requests":
            return _get_intercepted_requests(state, arguments)
        elif name == "forward_request":
            return await _forward_request(state, arguments)
        elif name == "drop_request":
            return await _drop_request(state, arguments)
        elif name == "set_proxy_intercept_state":
            return _set_proxy_intercept_state(state, arguments)
        elif name == "get_proxy_status":
            return _get_proxy_status(state, arguments)
        elif name == "replay_request":
            return await _replay_request(state, arguments)
        elif name == "extract_json_fields":
            return _extract_json_fields(state, arguments)
        elif name == "analyze_protection":
            return _analyze_protection(state, arguments)
        elif name == "add_log_note":
            return _add_log_note(state, arguments)
        elif name == "get_raw_http_message":
            return _get_raw_http_message(state, arguments)
        elif name == "get_config":
            return _get_config(state, arguments)
        elif name == "set_config":
            return _set_config(state, arguments)
        elif name == "url_encode":
            return _url_encode(arguments)
        elif name == "url_decode":
            return _url_decode(arguments)
        elif name == "base64_encode":
            return _base64_encode(arguments)
        elif name == "base64_decode":
            return _base64_decode(arguments)
        elif name == "generate_random_string":
            return _generate_random_string(arguments)
        else:
            return _error(f"Unknown tool: {name}")
    except Exception as e:
        logger.exception("Tool %s failed", name)
        return _error(str(e))


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

async def _send_http_request(state: AppState, args: dict) -> list[TextContent]:
    import httpx

    method = args["method"]
    url = args["url"]
    headers = args.get("headers", {})
    timeout = args.get("timeout_seconds", 30)

    body: bytes | None = None
    if args.get("body_base64"):
        body = base64.b64decode(args["body_base64"])
    elif args.get("body"):
        body = args["body"].encode("utf-8")

    proxy_url = f"http://127.0.0.1:{state.proxy_port}"

    async with httpx.AsyncClient(
        proxy=proxy_url,
        verify=False,
        timeout=timeout,
        http2=True,
    ) as client:
        resp = await client.request(method, url, headers=headers, content=body)

    # Build a log entry and insert synchronously for guaranteed log_id
    req_headers_dict: dict[str, list[str]] = {}
    for k, v in resp.request.headers.items():
        req_headers_dict.setdefault(k, []).append(v)

    resp_headers_dict: dict[str, list[str]] = {}
    for k, v in resp.headers.items():
        resp_headers_dict.setdefault(k, []).append(v)

    parsed = urllib.parse.urlparse(url)
    entry = HttpLogEntry(
        req_method=method,
        req_scheme=parsed.scheme or "https",
        req_host=parsed.hostname or "",
        req_port=parsed.port or (443 if parsed.scheme == "https" else 80),
        req_path=parsed.path or "/",
        req_http_version=f"HTTP/{resp.http_version}" if resp.http_version else "HTTP/1.1",
        req_headers=req_headers_dict,
        req_body=body,
        req_timestamp_ms=time.time() * 1000,
        resp_status_code=resp.status_code,
        resp_reason=resp.reason_phrase,
        resp_http_version=f"HTTP/{resp.http_version}" if resp.http_version else "HTTP/1.1",
        resp_headers=resp_headers_dict,
        resp_body=resp.content,
        resp_timestamp_ms=time.time() * 1000,
        duration_ms=resp.elapsed.total_seconds() * 1000 if resp.elapsed else None,
    )

    log_id = insert_http_log(state.db_pool, entry)

    resp_body_text = resp.content.decode("utf-8", errors="ignore") if resp.content else None
    is_binary = False
    if resp.content:
        try:
            resp.content.decode("utf-8")
        except UnicodeDecodeError:
            is_binary = True

    result = {
        "log_id": log_id,
        "status_code": resp.status_code,
        "reason": resp.reason_phrase,
        "http_version": resp.http_version,
        "headers": resp_headers_dict,
        "body": resp_body_text if not is_binary else None,
        "body_base64": base64.b64encode(resp.content).decode() if is_binary and resp.content else None,
        "body_is_binary": is_binary,
        "duration_ms": resp.elapsed.total_seconds() * 1000 if resp.elapsed else None,
    }
    return _json_result(result)


def _get_proxy_http_history(state: AppState, args: dict) -> list[TextContent]:
    count = min(args.get("count", 20), 200)
    offset = args.get("offset", 0)
    total, rows = get_http_logs(state.db_pool, count, offset)

    entries = []
    for r in rows:
        url = f"{r.get('req_scheme', 'http')}://{r['req_host']}"
        if r.get("req_port") and r["req_port"] not in (80, 443):
            url += f":{r['req_port']}"
        url += r.get("req_path", "/")
        entries.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "method": r["req_method"],
            "url": url[:5000],
            "status_code": r.get("resp_status_code"),
            "duration_ms": r.get("duration_ms"),
            "req_body_size": r.get("req_body_size") or 0,
            "resp_body_size": r.get("resp_body_size") or 0,
            "note": r.get("note"),
            "error": r.get("error_message"),
        })

    return _json_result({"total": total, "count": count, "offset": offset, "entries": entries})


def _get_proxy_http_history_regex(state: AppState, args: dict) -> list[TextContent]:
    pattern = args["pattern"]
    search_fields = args.get("search_fields")
    count = min(args.get("count", 20), 200)
    offset = args.get("offset", 0)

    total, rows = get_http_logs_regex(state.db_pool, pattern, search_fields, count, offset)

    entries = []
    for r in rows:
        url = f"{r.get('req_scheme', 'http')}://{r['req_host']}"
        if r.get("req_port") and r["req_port"] not in (80, 443):
            url += f":{r['req_port']}"
        url += r.get("req_path", "/")
        entries.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "method": r["req_method"],
            "url": url[:5000],
            "status_code": r.get("resp_status_code"),
            "duration_ms": r.get("duration_ms"),
            "req_body_size": r.get("req_body_size") or 0,
            "resp_body_size": r.get("resp_body_size") or 0,
            "note": r.get("note"),
            "error": r.get("error_message"),
        })

    return _json_result({"total": total, "count": count, "offset": offset, "entries": entries})


def _get_proxy_websocket_history(state: AppState, args: dict) -> list[TextContent]:
    count = min(args.get("count", 50), 500)
    offset = args.get("offset", 0)
    http_log_id = args.get("http_log_id")

    total, rows = get_ws_logs(state.db_pool, count, offset, http_log_id)

    entries = []
    for r in rows:
        payload = r.get("payload")
        payload_text = None
        payload_b64 = None
        if payload:
            if isinstance(payload, memoryview):
                payload = bytes(payload)
            if r.get("is_text"):
                payload_text = payload.decode("utf-8", errors="ignore")
            else:
                payload_b64 = base64.b64encode(payload).decode()

        entries.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "http_log_id": r.get("http_log_id"),
            "direction": r["direction"],
            "payload": payload_text,
            "payload_base64": payload_b64,
            "is_text": r.get("is_text"),
            "note": r.get("note"),
        })

    return _json_result({"total": total, "count": count, "offset": offset, "entries": entries})


def _get_proxy_websocket_history_regex(state: AppState, args: dict) -> list[TextContent]:
    pattern = args["pattern"]
    direction = args.get("direction")
    count = min(args.get("count", 50), 500)
    offset = args.get("offset", 0)

    total, rows = get_ws_logs_regex(state.db_pool, pattern, direction, count, offset)

    entries = []
    for r in rows:
        payload = r.get("payload")
        payload_text = None
        if payload:
            if isinstance(payload, memoryview):
                payload = bytes(payload)
            payload_text = payload.decode("utf-8", errors="ignore")
        entries.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "http_log_id": r.get("http_log_id"),
            "direction": r["direction"],
            "payload": payload_text,
            "is_text": r.get("is_text"),
            "note": r.get("note"),
        })

    return _json_result({"total": total, "count": count, "offset": offset, "entries": entries})


def _get_flow_details(state: AppState, args: dict) -> list[TextContent]:
    log_ids = args["log_ids"][:10]
    include_content = args.get("include_content", True)
    truncate_at = args.get("truncate_at", 2000)

    rows = get_http_logs_by_ids(state.db_pool, log_ids)
    entries = []
    for r in rows:
        url = f"{r.get('req_scheme', 'http')}://{r['req_host']}"
        if r.get("req_port") and r["req_port"] not in (80, 443):
            url += f":{r['req_port']}"
        url += r.get("req_path", "/")

        entry: dict[str, Any] = {
            "id": r["id"],
            "method": r["req_method"],
            "url": url,
            "status_code": r.get("resp_status_code"),
            "duration_ms": r.get("duration_ms"),
        }

        if include_content:
            req_headers = r.get("req_headers") or {}
            resp_headers = r.get("resp_headers") or {}

            entry["req_headers"] = req_headers
            entry["resp_headers"] = resp_headers

            # Request body
            req_ct = None
            if isinstance(req_headers, dict):
                for k, v in req_headers.items():
                    if k.lower() == "content-type":
                        req_ct = v if isinstance(v, str) else (v[0] if v else None)

            req_body = r.get("req_body")
            if req_body and isinstance(req_body, memoryview):
                req_body = bytes(req_body)
            body, trunc, preview = smart_body_content(req_body, req_ct, truncate_at)
            entry["req_body"] = body
            entry["req_body_truncated"] = trunc
            entry["req_body_is_preview"] = preview

            # Response body
            resp_ct = None
            if isinstance(resp_headers, dict):
                for k, v in resp_headers.items():
                    if k.lower() == "content-type":
                        resp_ct = v if isinstance(v, str) else (v[0] if v else None)

            resp_body = r.get("resp_body")
            if resp_body and isinstance(resp_body, memoryview):
                resp_body = bytes(resp_body)
            body, trunc, preview = smart_body_content(resp_body, resp_ct, truncate_at)
            entry["resp_body"] = body
            entry["resp_body_truncated"] = trunc
            entry["resp_body_is_preview"] = preview
            entry["resp_content_type"] = resp_ct

        entries.append(entry)

    return _json_result({"entries": entries})


def _set_intercept_rules(state: AppState, args: dict) -> list[TextContent]:
    rules_data = args["rules"]
    rules = []
    for rd in rules_data:
        rules.append(InterceptRule(
            methods=rd.get("methods", []),
            host_pattern=rd.get("host_pattern", ""),
            path_pattern=rd.get("path_pattern", ""),
            enabled=rd.get("enabled", True),
        ))
    with state.lock:
        state.intercept_rules = rules
    return _json_result({"rules_count": len(rules), "rules": [r.to_dict() for r in rules]})


def _get_intercepted_requests(state: AppState, args: dict) -> list[TextContent]:
    now = time.time()
    requests = []
    for flow_id, intercepted in state.intercept_queue.items():
        flow = intercepted.flow
        body = flow.request.raw_content
        body_text = None
        body_b64 = None
        is_binary = False

        if body:
            try:
                body_text = body.decode("utf-8")
            except UnicodeDecodeError:
                body_b64 = base64.b64encode(body).decode()
                is_binary = True

        seconds_waiting = now - intercepted.enqueued_at
        requests.append({
            "flow_id": flow_id,
            "queued_at": intercepted.enqueued_at,
            "seconds_waiting": round(seconds_waiting, 1),
            "timeout_in_seconds": round(max(0, state.intercept_timeout_s - seconds_waiting), 1),
            "method": flow.request.method,
            "url": flow.request.url,
            "headers": dict(flow.request.headers.items(multi=True)),
            "body": body_text,
            "body_base64": body_b64,
            "body_is_binary": is_binary,
        })

    return _json_result({"count": len(requests), "requests": requests})


async def _forward_request(state: AppState, args: dict) -> list[TextContent]:
    flow_id = args["flow_id"]
    intercepted = state.intercept_queue.get(flow_id)
    if not intercepted:
        return _error(f"No intercepted request with flow_id: {flow_id}")

    flow = intercepted.flow
    modifications = []

    if args.get("modify_method"):
        flow.request.method = args["modify_method"]
        modifications.append("method")
    if args.get("modify_url"):
        flow.request.url = args["modify_url"]
        modifications.append("url")
    if args.get("modify_headers"):
        for k, v in args["modify_headers"].items():
            if v is None:
                del flow.request.headers[k]
            else:
                flow.request.headers[k] = str(v)
        modifications.append("headers")
    if args.get("modify_body_base64"):
        flow.request.raw_content = base64.b64decode(args["modify_body_base64"])
        modifications.append("body")
    elif args.get("modify_body"):
        flow.request.text = args["modify_body"]
        modifications.append("body")

    # Signal the waiting hook in the mitmproxy thread
    if state.mitmproxy_loop:
        asyncio.run_coroutine_threadsafe(
            _set_event(intercepted.event), state.mitmproxy_loop
        )
    else:
        intercepted.event.set()

    return _json_result({"flow_id": flow_id, "forwarded": True, "modifications_applied": modifications})


async def _drop_request(state: AppState, args: dict) -> list[TextContent]:
    flow_id = args["flow_id"]
    intercepted = state.intercept_queue.get(flow_id)
    if not intercepted:
        return _error(f"No intercepted request with flow_id: {flow_id}")

    intercepted.flow.kill()

    if state.mitmproxy_loop:
        asyncio.run_coroutine_threadsafe(
            _set_event(intercepted.event), state.mitmproxy_loop
        )
    else:
        intercepted.event.set()

    return _json_result({"flow_id": flow_id, "dropped": True})


async def _set_event(event: asyncio.Event) -> None:
    event.set()


def _set_proxy_intercept_state(state: AppState, args: dict) -> list[TextContent]:
    previous = {
        "logging_enabled": state.logging_active.is_set(),
        "intercept_enabled": state.intercept_active.is_set(),
    }

    if "logging" in args:
        if args["logging"]:
            state.logging_active.set()
        else:
            state.logging_active.clear()

    if "intercept" in args:
        if args["intercept"]:
            state.intercept_active.set()
        else:
            state.intercept_active.clear()

    current = {
        "logging_enabled": state.logging_active.is_set(),
        "intercept_enabled": state.intercept_active.is_set(),
    }

    insert_config_snapshot(state.db_pool, current)

    return _json_result({**current, "previous": previous})


def _get_proxy_status(state: AppState, args: dict) -> list[TextContent]:
    db_ok = health_check(state.db_pool)
    proxy_running = state.mitmproxy_thread.is_alive() if state.mitmproxy_thread else False

    pool_info = {}
    try:
        pool_info = {
            "db_pool_size": state.db_pool.max_size if state.db_pool else 0,
            "db_pool_available": state.db_pool._pool.qsize() if state.db_pool and hasattr(state.db_pool, '_pool') else -1,
        }
    except Exception:
        pool_info = {"db_pool_size": -1, "db_pool_available": -1}

    return _json_result({
        "proxy_running": proxy_running,
        "proxy_port": state.proxy_port,
        "logging_enabled": state.logging_active.is_set(),
        "intercept_enabled": state.intercept_active.is_set(),
        "intercept_queue_depth": len(state.intercept_queue),
        "intercept_rules_count": len(state.intercept_rules),
        "write_queue_depth": state.queue.qsize() if state.queue else 0,
        "write_queue_maxsize": state.queue.maxsize if state.queue else 0,
        "dropped_count": state.dropped_count,
        "enqueued_total": state.enqueued_total,
        "db_connected": db_ok,
        **pool_info,
        "label": state.label,
        "uptime_seconds": round(time.monotonic() - state.start_time, 1),
    })


async def _replay_request(state: AppState, args: dict) -> list[TextContent]:
    import httpx

    log_id = args["log_id"]
    row = get_http_log_by_id(state.db_pool, log_id)
    if not row:
        return _error(f"No log entry with id: {log_id}")

    method = args.get("modify_method", row["req_method"])
    scheme = row.get("req_scheme", "https")
    host = row["req_host"]
    port = row["req_port"]
    path = row.get("req_path", "/")

    if args.get("modify_url"):
        url = args["modify_url"]
    else:
        url = f"{scheme}://{host}"
        if port and port not in (80, 443):
            url += f":{port}"
        url += path

    headers = row.get("req_headers") or {}
    if isinstance(headers, str):
        headers = json.loads(headers)
    # Flatten header lists to single values for httpx
    flat_headers = {}
    for k, v in headers.items():
        flat_headers[k] = v[0] if isinstance(v, list) else v

    if args.get("modify_headers"):
        for k, v in args["modify_headers"].items():
            if v is None:
                flat_headers.pop(k, None)
            else:
                flat_headers[k] = str(v)

    body: bytes | None = None
    if args.get("modify_body_base64"):
        body = base64.b64decode(args["modify_body_base64"])
    elif args.get("modify_body"):
        body = args["modify_body"].encode("utf-8")
    else:
        raw = row.get("req_body")
        if raw:
            body = bytes(raw) if isinstance(raw, memoryview) else raw

    proxy_url = f"http://127.0.0.1:{state.proxy_port}"

    async with httpx.AsyncClient(proxy=proxy_url, verify=False, timeout=30, http2=True) as client:
        resp = await client.request(method, url, headers=flat_headers, content=body)

    # Synchronous insert for log_id
    parsed = urllib.parse.urlparse(url)
    req_headers_dict: dict[str, list[str]] = {}
    for k, v in resp.request.headers.items():
        req_headers_dict.setdefault(k, []).append(v)
    resp_headers_dict: dict[str, list[str]] = {}
    for k, v in resp.headers.items():
        resp_headers_dict.setdefault(k, []).append(v)

    entry = HttpLogEntry(
        req_method=method,
        req_scheme=parsed.scheme or "https",
        req_host=parsed.hostname or host,
        req_port=parsed.port or port,
        req_path=parsed.path or "/",
        req_http_version=f"HTTP/{resp.http_version}" if resp.http_version else "HTTP/1.1",
        req_headers=req_headers_dict,
        req_body=body,
        req_timestamp_ms=time.time() * 1000,
        resp_status_code=resp.status_code,
        resp_reason=resp.reason_phrase,
        resp_http_version=f"HTTP/{resp.http_version}" if resp.http_version else "HTTP/1.1",
        resp_headers=resp_headers_dict,
        resp_body=resp.content,
        resp_timestamp_ms=time.time() * 1000,
        duration_ms=resp.elapsed.total_seconds() * 1000 if resp.elapsed else None,
    )
    new_id = insert_http_log(state.db_pool, entry)

    return _json_result({
        "new_log_id": new_id,
        "original_log_id": log_id,
        "status_code": resp.status_code,
        "duration_ms": resp.elapsed.total_seconds() * 1000 if resp.elapsed else None,
    })


def _extract_json_fields(state: AppState, args: dict) -> list[TextContent]:
    log_id = args["log_id"]
    content_type = args["content_type"]
    json_paths = args["json_paths"]

    row = get_http_log_by_id(state.db_pool, log_id)
    if not row:
        return _error(f"No log entry with id: {log_id}")

    body_key = "req_body" if content_type == "request" else "resp_body"
    body = row.get(body_key)
    if not body:
        return _error(f"No {content_type} body for log {log_id}")

    if isinstance(body, memoryview):
        body = bytes(body)

    try:
        text = body.decode("utf-8")
        data = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return _error(f"Body is not valid JSON: {e}")

    results = {}
    for path in json_paths:
        results[path] = extract_json_path(data, path)

    return _json_result({"log_id": log_id, "results": results})


def _analyze_protection(state: AppState, args: dict) -> list[TextContent]:
    log_id = args["log_id"]
    extract_scripts = args.get("extract_scripts", True)

    row = get_http_log_by_id(state.db_pool, log_id)
    if not row:
        return _error(f"No log entry with id: {log_id}")

    result = analyze_protection_for_log(row, extract_scripts)
    return _json_result(result)


def _add_log_note(state: AppState, args: dict) -> list[TextContent]:
    log_id = args["log_id"]
    note = args["note"][:4000]
    log_type = args.get("log_type", "http")

    table = "http_logs" if log_type == "http" else "ws_logs"
    updated = update_note(state.db_pool, table, log_id, note)

    if not updated:
        return _error(f"No {log_type} log entry with id: {log_id}")

    return _json_result({"log_id": log_id, "log_type": log_type, "note": note})


def _get_raw_http_message(state: AppState, args: dict) -> list[TextContent]:
    log_id = args["log_id"]
    include = args.get("include", "both")
    body_encoding = args.get("body_encoding", "auto")

    row = get_http_log_by_id(state.db_pool, log_id)
    if not row:
        return _error(f"No log entry with id: {log_id}")

    result: dict[str, Any] = {"log_id": log_id}

    if include in ("request", "both"):
        req_line = f"{row['req_method']} {row.get('req_path', '/')} {row.get('req_http_version', 'HTTP/1.1')}\r\n"
        headers = row.get("req_headers") or {}
        if isinstance(headers, str):
            headers = json.loads(headers)
        header_lines = ""
        for k, v in headers.items():
            vals = v if isinstance(v, list) else [v]
            for val in vals:
                header_lines += f"{k}: {val}\r\n"

        body_str, enc = _encode_body(row.get("req_body"), body_encoding)
        result["request_raw"] = req_line + header_lines + "\r\n" + body_str
        result["request_body_encoding"] = enc

    if include in ("response", "both"):
        status = row.get("resp_status_code", "")
        reason = row.get("resp_reason", "")
        version = row.get("resp_http_version", "HTTP/1.1")
        resp_line = f"{version} {status} {reason}\r\n"

        headers = row.get("resp_headers") or {}
        if isinstance(headers, str):
            headers = json.loads(headers)
        header_lines = ""
        for k, v in headers.items():
            vals = v if isinstance(v, list) else [v]
            for val in vals:
                header_lines += f"{k}: {val}\r\n"

        body_str, enc = _encode_body(row.get("resp_body"), body_encoding)
        result["response_raw"] = resp_line + header_lines + "\r\n" + body_str
        result["response_body_encoding"] = enc

    return _json_result(result)


def _encode_body(body: bytes | memoryview | None, encoding: str) -> tuple[str, str]:
    if body is None:
        return "", "none"
    if isinstance(body, memoryview):
        body = bytes(body)

    if encoding == "omit":
        return f"[body omitted, {len(body)} bytes]", "omit"
    elif encoding == "base64":
        return base64.b64encode(body).decode(), "base64"
    elif encoding == "utf8":
        return body.decode("utf-8", errors="replace"), "utf8"
    else:  # auto
        try:
            return body.decode("utf-8"), "utf8"
        except UnicodeDecodeError:
            return base64.b64encode(body).decode(), "base64"


def _get_config(state: AppState, args: dict) -> list[TextContent]:
    return _json_result({
        "logging_enabled": state.logging_active.is_set(),
        "intercept_enabled": state.intercept_active.is_set(),
        "intercept_rules": [r.to_dict() for r in state.intercept_rules],
        "proxy_port": state.proxy_port,
        "label": state.label,
        "queue_maxsize": state.queue.maxsize if state.queue else 0,
    })


def _set_config(state: AppState, args: dict) -> list[TextContent]:
    updated = []
    with state.lock:
        if "logging_enabled" in args:
            if args["logging_enabled"]:
                state.logging_active.set()
            else:
                state.logging_active.clear()
            updated.append("logging_enabled")
        if "label" in args:
            state.label = args["label"][:200]
            updated.append("label")

    config = {
        "logging_enabled": state.logging_active.is_set(),
        "proxy_port": state.proxy_port,
        "label": state.label,
    }
    insert_config_snapshot(state.db_pool, config)

    return _json_result({"updated_fields": updated, "config": config})


# ---------------------------------------------------------------------------
# Encoding / Utility tools
# ---------------------------------------------------------------------------

def _url_encode(args: dict) -> list[TextContent]:
    return _json_result({"encoded": urllib.parse.quote(args["value"], safe=args.get("safe", ""))})


def _url_decode(args: dict) -> list[TextContent]:
    return _json_result({"decoded": urllib.parse.unquote(args["value"])})


def _base64_encode(args: dict) -> list[TextContent]:
    data = args["value"].encode("utf-8")
    if args.get("url_safe"):
        encoded = base64.urlsafe_b64encode(data).decode()
    else:
        encoded = base64.b64encode(data).decode()
    return _json_result({"encoded": encoded})


def _base64_decode(args: dict) -> list[TextContent]:
    if args.get("url_safe"):
        decoded = base64.urlsafe_b64decode(args["value"])
    else:
        decoded = base64.b64decode(args["value"])

    result: dict[str, Any] = {"hex": decoded.hex()}
    if args.get("as_text", True):
        result["decoded"] = decoded.decode("utf-8", errors="replace")
    return _json_result(result)


def _generate_random_string(args: dict) -> list[TextContent]:
    length = min(args["length"], 4096)
    charset_name = args.get("charset", "alphanumeric")

    charsets = {
        "alphanumeric": string.ascii_letters + string.digits,
        "alpha": string.ascii_letters,
        "numeric": string.digits,
        "hex": string.hexdigits[:16],
        "base64": string.ascii_letters + string.digits + "+/",
        "printable": string.printable.strip(),
    }

    charset = charsets.get(charset_name, charset_name)
    value = "".join(secrets.choice(charset) for _ in range(length))
    return _json_result({"value": value, "length": length, "charset": charset_name})


# ---------------------------------------------------------------------------
# Server runner
# ---------------------------------------------------------------------------

async def run_mcp_server() -> None:
    """Run the MCP server on stdio."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )
