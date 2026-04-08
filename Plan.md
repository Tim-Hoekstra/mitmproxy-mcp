# mitmproxy MCP — Complete Design Plan

## Overview

A Dockerised mitmproxy-based HTTP/WebSocket interception and logging tool controlled entirely
through an MCP server. AI agents interact with the proxy exclusively via MCP tools — there is
no REST API. All captured traffic is persisted to PostgreSQL. The proxy supports live request
interception with MCP-driven modification before forwarding.

---

## Architecture

```
┌─ Docker Compose ────────────────────────────────────────────────────────────────┐
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  app container  (Python 3.12)                                           │   │
│  │                                                                         │   │
│  │  Thread 1 (daemon)                    Thread 2 (main)                   │   │
│  │  ─────────────────────────────        ──────────────────────────────    │   │
│  │  mitmproxy engine                     MCP Server (stdio transport)      │   │
│  │  + LoggingAddon                       32 MCP tools                      │   │
│  │  port :8080                                                              │   │
│  │       │                                      │                          │   │
│  │       │  threading.Queue (50k max)            │  reads AppState          │   │
│  │       └──────────────────────────────────────┘  via threading.Lock      │   │
│  │                      │                                                   │   │
│  │                      ▼  Thread 3 (daemon)                                │   │
│  │              ─────────────────────────                                   │   │
│  │              DB Writer                                                    │   │
│  │              drains queue in batches                                      │   │
│  │              psycopg3 sync driver                                         │   │
│  └──────────────────────┬──────────────────────────────────────────────────┘   │
│                         │                                                       │
│  ┌──────────────────────▼──────────────┐  ┌────────────────────────────────┐   │
│  │  postgres:16  (port :5432)           │  │  adminer  (port :8082)         │   │
│  └─────────────────────────────────────┘  └────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘

External clients configure HTTP(S) proxy to host:8080
CA cert served from named Docker volume (trust once, persists across restarts)
MCP agent connects via: docker exec -i <container> python -m mitmproxy_mcp.main
```

---

## Threading Model

### Thread 1 — mitmproxy (daemon)

- Started via `threading.Thread(target=_run_mitmproxy, daemon=True)`.
- Runs `DumpMaster` with the `LoggingAddon` injected. Blocks on its own asyncio event loop.
- Captures the loop reference (`asyncio.get_event_loop()`) at startup into `AppState.mitmproxy_loop`.
  This reference is used by the MCP thread to signal intercepted flows via
  `asyncio.run_coroutine_threadsafe`.
- Checks `AppState.logging_active` (a `threading.Event`) at the top of every hook.
- Checks `AppState.intercept_active` (a `threading.Event`) to decide whether to hold requests.
- On shutdown signal, calls `master.shutdown()`.

### Thread 2 — MCP Server (main thread)

- Calls `mcp.run(transport="stdio")` which blocks on stdin.
- All tool handlers are synchronous functions (simpler than async; psycopg3 sync driver).
- DB reads are executed directly against the connection pool.
- AppState mutations (e.g. `set_proxy_intercept_state`, `set_config`) acquire `AppState.lock`.
- Interception tools call `asyncio.run_coroutine_threadsafe(event.set(), app_state.mitmproxy_loop)`
  to wake suspended request hooks in Thread 1.

### Thread 3 — DB Writer (daemon)

- Started via `threading.Thread(target=_db_writer_loop, daemon=True)`.
- Loop: `queue.get(timeout=0.1)` — short timeout allows clean shutdown via stop event.
- Batches up to 100 items or flushes after 500 ms of inactivity (whichever comes first).
- Executes a single `executemany` per batch — one round-trip per flush.
- On `queue.Full` (producer side in Thread 1): increments `AppState.dropped_count`.
- Periodically snapshots `queue.qsize()` into `AppState.queue_depth` for `/get_proxy_status`.

### Queue Design

```
threading.Queue(maxsize=50_000)

Item types (typed dataclasses from queue_types.py):
  HttpLogEntry   — enqueued from addon.response() and addon.error()
  WsLogEntry     — enqueued from addon.websocket_message()
```

Queue full policy: `put(block=True, timeout=0.05)` — block 50 ms then drop and increment
`dropped_count`. Short enough to not stall the proxy under burst load; long enough to absorb
momentary DB hiccups.

---

## Docker Compose

```yaml
services:

  app:
    build: .
    ports:
      - "8080:8080"          # mitmproxy proxy listener
    environment:
      PROXY_PORT:       "8080"
      DB_DSN:           "postgresql://mitmuser:mitmpass@postgres:5432/mitmdb"
      QUEUE_MAXSIZE:    "50000"
      DB_BATCH_SIZE:    "100"
      DB_FLUSH_MS:      "500"
      INTERCEPT_TIMEOUT_S: "60"
      LOG_LEVEL:        "INFO"
    volumes:
      - mitmproxy_certs:/root/.mitmproxy
    stdin_open: true
    tty: true
    depends_on:
      postgres:
        condition: service_healthy

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER:     mitmuser
      POSTGRES_PASSWORD: mitmpass
      POSTGRES_DB:       mitmdb
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U mitmuser -d mitmdb"]
      interval: 5s
      timeout: 3s
      retries: 10

  adminer:
    image: adminer:latest
    ports:
      - "8082:8080"
    depends_on:
      - postgres

volumes:
  pgdata:
  mitmproxy_certs:
```

---

## Database Schema

### Table: `http_logs`

```sql
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS http_logs (
    id                  BIGSERIAL PRIMARY KEY,
    created_at          TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    -- Request
    req_method          TEXT                NOT NULL,
    req_scheme          TEXT                NOT NULL,   -- http / https
    req_host            TEXT                NOT NULL,
    req_port            INTEGER             NOT NULL,
    req_path            TEXT                NOT NULL,
    req_http_version    TEXT                NOT NULL,   -- HTTP/1.1 / HTTP/2.0
    req_headers         JSONB               NOT NULL DEFAULT '{}',
    req_body            BYTEA,
    req_timestamp_ms    DOUBLE PRECISION    NOT NULL,

    -- Response (nullable — may be absent on error)
    resp_status_code    INTEGER,
    resp_reason         TEXT,
    resp_http_version   TEXT,
    resp_headers        JSONB,
    resp_body           BYTEA,
    resp_timestamp_ms   DOUBLE PRECISION,

    -- Derived
    duration_ms         DOUBLE PRECISION,
    error_message       TEXT,

    -- Annotation
    note                TEXT,
    tags                TEXT[]
);

CREATE INDEX IF NOT EXISTS idx_http_logs_created_at  ON http_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_http_logs_req_host    ON http_logs (req_host);
CREATE INDEX IF NOT EXISTS idx_http_logs_req_method  ON http_logs (req_method);
CREATE INDEX IF NOT EXISTS idx_http_logs_resp_status ON http_logs (resp_status_code);
CREATE INDEX IF NOT EXISTS idx_http_logs_host_trgm   ON http_logs USING gin (req_host  gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_http_logs_path_trgm   ON http_logs USING gin (req_path  gin_trgm_ops);
```

### Table: `ws_logs`

```sql
CREATE TABLE IF NOT EXISTS ws_logs (
    id              BIGSERIAL PRIMARY KEY,
    created_at      TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    http_log_id     BIGINT              REFERENCES http_logs(id) ON DELETE SET NULL,
    direction       TEXT                NOT NULL
                        CHECK (direction IN ('CLIENT_TO_SERVER','SERVER_TO_CLIENT')),
    payload         BYTEA               NOT NULL,
    is_text         BOOLEAN             NOT NULL DEFAULT TRUE,
    timestamp_ms    DOUBLE PRECISION    NOT NULL,
    note            TEXT
);

CREATE INDEX IF NOT EXISTS idx_ws_logs_created_at  ON ws_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ws_logs_http_log_id ON ws_logs (http_log_id);
```

### Table: `config_snapshots`

```sql
CREATE TABLE IF NOT EXISTS config_snapshots (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by  TEXT        NOT NULL DEFAULT 'agent',
    config_json JSONB       NOT NULL
);
```

---

## AppState

Shared mutable object constructed once at startup, passed by reference to all components.

```
AppState
  ── config (protected by lock) ──────────────────────────────────
  lock:                threading.Lock
  logging_active:      threading.Event   # set = logging ON
  intercept_active:    threading.Event   # set = interception ON
  intercept_rules:     list[InterceptRule]
  proxy_port:          int               # read-only after startup
  label:               str

  ── stats (GIL-safe int reads; lock for consistent snapshots) ───
  dropped_count:       int
  enqueued_total:      int
  queue_depth:         int               # updated by writer thread

  ── runtime refs ────────────────────────────────────────────────
  queue:               threading.Queue
  db_pool:             ConnectionPool    # psycopg_pool
  mitmproxy_loop:      asyncio.AbstractEventLoop   # captured at Thread 1 start
  start_time:          float             # time.monotonic() at startup

  ── interception state (mitmproxy thread only — no lock needed) ─
  intercept_queue:     dict[str, InterceptedFlow]
                         flow_id → {flow, asyncio.Event, enqueued_at}
  flow_to_log_id:      dict[str, int]
                         flow_id → http_logs.id  (for WS linkage)

InterceptRule
  methods:             list[str]   # empty = match all methods
  host_pattern:        str         # regex; empty = match all hosts
  path_pattern:        str         # regex; empty = match all paths
  enabled:             bool
```

---

## mitmproxy Addon Design

### `addon.py` — `LoggingAddon`

Injected into mitmproxy at startup. Holds references to `AppState` and the write queue.

#### Hook: `request(flow)`

1. If `logging_active` not set → return immediately.
2. Record `flow.metadata["req_ts"] = flow.request.timestamp_start`.
3. If `intercept_active` is set AND flow matches any `intercept_rules`:
   a. Create `asyncio.Event` for this flow.
   b. Store in `app_state.intercept_queue[flow.id]`.
   c. `await asyncio.wait_for(event.wait(), timeout=INTERCEPT_TIMEOUT_S)`.
      - Yields the event loop — other flows continue normally.
   d. On timeout: log warning, remove from queue, forward unmodified.
   e. On event set: read any modifications written to the flow object, then return.

#### Hook: `response(flow)`

1. If `logging_active` not set → return immediately.
2. Build `HttpLogEntry` from `flow.request` and `flow.response`.
3. `duration_ms = (flow.response.timestamp_end - flow.request.timestamp_start) * 1000`.
4. `queue.put(entry, block=True, timeout=0.05)` — on `Full`, increment `dropped_count`.

#### Hook: `error(flow)`

1. If `logging_active` not set → return.
2. Build partial `HttpLogEntry` with `error_message = flow.error.msg`, no response fields.
3. Same enqueue-or-drop pattern.

#### Hook: `websocket_message(flow)`

1. If `logging_active` not set → return.
2. `msg = flow.websocket.messages[-1]`.
3. Lookup `http_log_id = app_state.flow_to_log_id.get(flow.id)` (may be None if upgrade
   insert is still queued — ws_logs.http_log_id is nullable).
4. Build `WsLogEntry(http_log_id, direction, payload, is_text, timestamp_ms)`.
5. Enqueue.

#### Hook: `websocket_end(flow)`

- Remove `flow.id` from `flow_to_log_id` to prevent unbounded growth.

#### Rule Matching (helper)

```
_matches_rules(flow, rules) -> bool:
  if not rules: return True          # no rules = intercept everything
  for rule in rules:
    if not rule.enabled: continue
    method_ok = (not rule.methods) or (flow.request.method in rule.methods)
    host_ok   = (not rule.host_pattern) or re.search(rule.host_pattern, flow.request.host)
    path_ok   = (not rule.path_pattern) or re.search(rule.path_pattern, flow.request.path)
    if method_ok and host_ok and path_ok: return True
  return False
```

---

## MCP Tools — Full Inventory (32 tools)

### Category 1 — HTTP Request Tools (1)

#### `send_http_request`
Send a crafted HTTP request through the running mitmproxy instance and return the full response.
Uses `httpx` with the proxy set to `http://localhost:{proxy_port}`. The request travels through
mitmproxy, is logged by the addon, and the response is returned to the agent.
To guarantee a `log_id` in the response, this tool performs a **synchronous DB insert** (bypasses
the async queue), then returns.

Parameters:
- `method` (string, required)
- `url` (string, required)
- `headers` (object, optional)
- `body` (string, optional) — UTF-8 body
- `body_base64` (string, optional) — binary body; takes precedence over `body`
- `timeout_seconds` (number, optional, default 30)

Returns:
```json
{
  "log_id": 1234,
  "status_code": 200,
  "reason": "OK",
  "http_version": "HTTP/1.1",
  "headers": {"Content-Type": ["application/json"]},
  "body": "...",
  "body_base64": null,
  "body_is_binary": false,
  "duration_ms": 142.3
}
```

---

### Category 2 — Proxy History Tools (5)

#### `get_proxy_http_history`
Paginated HTTP log, newest-first. List view only — no bodies (use `get_raw_http_message` or
`get_flow_details` for full content). Burp-style 5000-char truncation applied to URL display.

Parameters:
- `count` (integer, optional, default 20, max 200)
- `offset` (integer, optional, default 0)

Returns:
```json
{
  "total": 5021,
  "count": 20,
  "offset": 0,
  "entries": [
    {
      "id": 5021,
      "created_at": "2026-04-08T12:00:00Z",
      "method": "GET",
      "url": "https://example.com/api/users",
      "status_code": 200,
      "duration_ms": 88.2,
      "req_body_size": 0,
      "resp_body_size": 1402,
      "note": null,
      "error": null
    }
  ]
}
```

---

#### `get_proxy_http_history_regex`
Regex search across HTTP history. Uses PostgreSQL `~*` (case-insensitive POSIX regex).
Body fields are cast from BYTEA to TEXT with `convert_from`. Headers searched via
`jsonb_each_text`. Hard cap of 200 results to prevent runaway full-table-scan queries.

Parameters:
- `pattern` (string, required) — POSIX regex
- `search_fields` (array of string, optional, default all)
  — options: `url`, `req_headers`, `resp_headers`, `req_body`, `resp_body`
- `count` (integer, optional, default 20, max 200)
- `offset` (integer, optional, default 0)

Returns: same shape as `get_proxy_http_history`.

---

#### `get_proxy_websocket_history`
Paginated WebSocket message log.

Parameters:
- `count` (integer, optional, default 50, max 500)
- `offset` (integer, optional, default 0)
- `http_log_id` (integer, optional) — filter to one WS connection

Returns:
```json
{
  "total": 312,
  "count": 50,
  "offset": 0,
  "entries": [
    {
      "id": 312,
      "created_at": "2026-04-08T12:01:00Z",
      "http_log_id": 4800,
      "direction": "CLIENT_TO_SERVER",
      "payload": "...",
      "payload_base64": null,
      "is_text": true,
      "note": null
    }
  ]
}
```

---

#### `get_proxy_websocket_history_regex`
Regex filter over WebSocket payload content. Skips binary frames silently.

Parameters:
- `pattern` (string, required)
- `direction` (string, optional) — `CLIENT_TO_SERVER` or `SERVER_TO_CLIENT`
- `count` (integer, optional, default 50, max 500)
- `offset` (integer, optional, default 0)

Returns: same shape as `get_proxy_websocket_history`.

---

#### `get_flow_details`
Retrieve full request and response detail for one or more log entries. Applies smart content
handling borrowed from lucasoeth/mitmproxy-mcp:
- Bodies ≤ 2000 bytes: returned as-is (UTF-8 string or base64 if binary).
- JSON bodies > 2000 bytes: returned as a **structure preview** — keys preserved, leaf values
  replaced with type indicators (e.g. `"[string]"`, `"[10 items]"`). Agent can drill in with
  `extract_json_fields`.
- Non-JSON bodies > 2000 bytes: truncated with `...[truncated N bytes]` marker.

Parameters:
- `log_ids` (array of integer, required) — up to 10 IDs per call
- `include_content` (boolean, optional, default true)
- `truncate_at` (integer, optional, default 2000) — byte threshold for truncation/preview

Returns:
```json
{
  "entries": [
    {
      "id": 1234,
      "method": "POST",
      "url": "https://api.example.com/graphql",
      "status_code": 200,
      "req_headers": {"Content-Type": "application/json"},
      "req_body": "{\"query\": \"...\"}",
      "req_body_truncated": false,
      "resp_headers": {"Content-Type": "application/json"},
      "resp_body": {"data": {"users": "[50 items]"}, "meta": {"...": "3 keys"}},
      "resp_body_truncated": true,
      "resp_body_is_preview": true,
      "resp_content_type": "application/json",
      "duration_ms": 55.1
    }
  ]
}
```

---

### Category 3 — Interception Tools (4)

#### `set_intercept_rules`
Configure which requests are held for inspection/modification. Setting rules does not
automatically enable interception — call `set_proxy_intercept_state` with `intercept=true`.

Parameters:
- `rules` (array of object, required) — empty array = intercept all traffic
  - `methods` (array of string, optional) — e.g. `["POST","PUT"]`; empty = all methods
  - `host_pattern` (string, optional) — POSIX regex; e.g. `"api\\.example\\.com"`
  - `path_pattern` (string, optional) — POSIX regex; e.g. `"/admin/.*"`
  - `enabled` (boolean, optional, default true)

Returns:
```json
{"rules_count": 2, "rules": [...]}
```

---

#### `get_intercepted_requests`
List all requests currently held in the intercept queue waiting for a decision.
Each entry includes the full request so the agent can inspect it before deciding.

Parameters: none

Returns:
```json
{
  "count": 3,
  "requests": [
    {
      "flow_id": "abc123",
      "queued_at": "2026-04-08T12:00:00Z",
      "seconds_waiting": 4.2,
      "timeout_in_seconds": 55.8,
      "method": "POST",
      "url": "https://api.example.com/login",
      "headers": {"Content-Type": "application/json", "Authorization": "Bearer ..."},
      "body": "{\"username\":\"admin\",\"password\":\"secret\"}",
      "body_base64": null,
      "body_is_binary": false
    }
  ]
}
```

---

#### `forward_request`
Release a held request, optionally with modifications. The suspended `request` hook in
Thread 1 wakes via `asyncio.run_coroutine_threadsafe` and forwards the (modified) request
upstream. The response is logged normally.

Parameters:
- `flow_id` (string, required)
- `modify_headers` (object, optional) — headers to add or override; set value to `null` to remove
- `modify_body` (string, optional) — replace body with UTF-8 string
- `modify_body_base64` (string, optional) — replace body with base64 bytes
- `modify_url` (string, optional) — replace the full URL
- `modify_method` (string, optional) — replace the HTTP method

Returns:
```json
{
  "flow_id": "abc123",
  "forwarded": true,
  "modifications_applied": ["headers", "body"]
}
```

---

#### `drop_request`
Kill a held request. mitmproxy sends a connection error back to the client. The flow is
logged as an error entry with `error_message: "dropped by agent"`.

Parameters:
- `flow_id` (string, required)
- `reason` (string, optional) — stored in `http_logs.error_message`

Returns:
```json
{"flow_id": "abc123", "dropped": true}
```

---

### Category 4 — Proxy Control Tools (3)

#### `set_proxy_intercept_state`
Toggle logging and/or interception independently.

Parameters:
- `logging` (boolean, optional) — enable/disable traffic logging to DB
- `intercept` (boolean, optional) — enable/disable request interception queue

Returns:
```json
{
  "logging_enabled": true,
  "intercept_enabled": false,
  "previous": {"logging_enabled": true, "intercept_enabled": true}
}
```

---

#### `get_proxy_status`
Health snapshot of all subsystems.

Parameters: none

Returns:
```json
{
  "proxy_running": true,
  "proxy_port": 8080,
  "logging_enabled": true,
  "intercept_enabled": false,
  "intercept_queue_depth": 0,
  "intercept_rules_count": 2,
  "write_queue_depth": 14,
  "write_queue_maxsize": 50000,
  "dropped_count": 0,
  "enqueued_total": 5021,
  "db_connected": true,
  "db_pool_size": 10,
  "db_pool_available": 9,
  "label": "pentest-session-1",
  "uptime_seconds": 3612.4
}
```

---

#### `replay_request`
Fetch a logged request by ID, optionally modify it, re-send through the proxy, and return
the new log entry ID.

Parameters:
- `log_id` (integer, required)
- `modify_headers` (object, optional)
- `modify_body` (string, optional)
- `modify_body_base64` (string, optional)
- `modify_url` (string, optional)
- `modify_method` (string, optional)

Returns:
```json
{
  "new_log_id": 5022,
  "original_log_id": 4991,
  "status_code": 403,
  "duration_ms": 55.1
}
```

---

### Category 5 — Analysis Tools (2)

#### `extract_json_fields`
Extract specific fields from a request or response JSON body using JSONPath expressions.
Useful for drilling into large JSON bodies after `get_flow_details` returns a structure preview.

Parameters:
- `log_id` (integer, required)
- `content_type` (string, required) — `"request"` or `"response"`
- `json_paths` (array of string, required) — e.g. `["$.data.users[0].id", "$.meta.total"]`

Returns:
```json
{
  "log_id": 1234,
  "results": {
    "$.data.users[0].id": 42,
    "$.meta.total": 1000,
    "$.nonexistent.path": null
  }
}
```

JSONPath support: dot notation, array indexing, quoted keys. Custom parser — no external library.

---

#### `analyze_protection`
Analyse a response for bot protection and WAF mechanisms. Detects vendor, scores confidence,
extracts JavaScript analysis, and provides remediation suggestions.
Inspired by lucasoeth/mitmproxy-mcp's `analyze_protection` tool, adapted for live DB records.

Parameters:
- `log_id` (integer, required)
- `extract_scripts` (boolean, optional, default true) — extract and analyse inline JavaScript

Returns:
```json
{
  "log_id": 1234,
  "protection_systems": [
    {"vendor": "Cloudflare", "confidence": 83, "matched_signatures": ["cf-ray header", "__cf_bm cookie"]}
  ],
  "challenge_analysis": {
    "type": "javascript",
    "status_code_suspicious": true,
    "indicators": ["cf-mitigated header present"]
  },
  "request_cookies": [{"name": "__cf_bm", "protection_indicator": true, "vendor": "Cloudflare"}],
  "response_cookies": [{"name": "cf_clearance", "protection_indicator": true, "vendor": "Cloudflare"}],
  "scripts": [
    {
      "type": "inline",
      "size_bytes": 4200,
      "obfuscation_score": 72,
      "fingerprinting_techniques": ["canvas", "webgl", "navigator"],
      "is_likely_protection": true
    }
  ],
  "suggestions": [
    "Check for cf_clearance cookie propagation",
    "Consider using cloudscraper for automated access"
  ]
}
```

Detected vendors: Cloudflare, Akamai Bot Manager, PerimeterX, DataDome, reCAPTCHA, hCaptcha,
generic bot detection patterns.

---

### Category 6 — Annotation Tools (1)

#### `add_log_note`
Attach a free-text annotation to an `http_logs` or `ws_logs` row.

Parameters:
- `log_id` (integer, required)
- `note` (string, required, max 4000 chars)
- `log_type` (string, optional, default `"http"`) — `"http"` or `"websocket"`

Returns:
```json
{"log_id": 1234, "log_type": "http", "note": "SQL injection candidate — test this endpoint"}
```

---

### Category 7 — Raw Wire Format Tools (1)

#### `get_raw_http_message`
Return a log entry as a raw HTTP wire-format string. Useful for diffing, feeding into other
tools, or AI inspection of the full message structure.

Parameters:
- `log_id` (integer, required)
- `include` (string, optional, default `"both"`) — `"request"`, `"response"`, or `"both"`
- `body_encoding` (string, optional, default `"auto"`) — `"auto"` (UTF-8 if valid, else base64),
  `"base64"`, `"utf8"`, `"omit"`

Returns:
```json
{
  "log_id": 1234,
  "request_raw":  "POST /api/login HTTP/1.1\r\nHost: example.com\r\n\r\n{...}",
  "response_raw": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{...}",
  "request_body_encoding":  "utf8",
  "response_body_encoding": "utf8"
}
```

---

### Category 8 — Configuration Tools (2)

#### `get_config`
Return current proxy configuration.

Parameters: none

Returns:
```json
{
  "logging_enabled": true,
  "intercept_enabled": false,
  "intercept_rules": [],
  "proxy_port": 8080,
  "label": "pentest-session-1",
  "queue_maxsize": 50000
}
```

---

#### `set_config`
Update proxy configuration. Persists change to `config_snapshots`.
`proxy_port` is not hot-reloadable (requires container restart).

Parameters:
- `logging_enabled` (boolean, optional)
- `label` (string, optional, max 200 chars)

Returns:
```json
{
  "updated_fields": ["label"],
  "config": {"logging_enabled": true, "proxy_port": 8080, "label": "new-label"}
}
```

---

### Category 9 — Encoding / Utility Tools (5)

#### `url_encode`
Parameters: `value` (string), `safe` (string, optional, default `""`)
Returns: `{"encoded": "hello%20world"}`

#### `url_decode`
Parameters: `value` (string)
Returns: `{"decoded": "hello world"}`

#### `base64_encode`
Parameters: `value` (string), `url_safe` (boolean, optional, default false)
Returns: `{"encoded": "aGVsbG8gd29ybGQ="}`

#### `base64_decode`
Parameters: `value` (string), `url_safe` (boolean, optional, default false),
`as_text` (boolean, optional, default true)
Returns: `{"decoded": "hello world", "hex": "68656c6c6f20776f726c64"}`

#### `generate_random_string`
Uses Python `secrets` module (cryptographically random).
Parameters: `length` (integer, max 4096), `charset` (string, optional, default `"alphanumeric"`)
— options: `"alphanumeric"`, `"alpha"`, `"numeric"`, `"hex"`, `"base64"`, `"printable"`,
or any custom string of allowed characters.
Returns: `{"value": "xK7mP2nQ", "length": 8, "charset": "alphanumeric"}`

---

## Tool Summary

| # | Category              | Tool                            |
|---|-----------------------|---------------------------------|
| 1 | HTTP Request          | `send_http_request`             |
| 2 | Proxy History         | `get_proxy_http_history`        |
| 3 | Proxy History         | `get_proxy_http_history_regex`  |
| 4 | Proxy History         | `get_proxy_websocket_history`   |
| 5 | Proxy History         | `get_proxy_websocket_history_regex` |
| 6 | Proxy History         | `get_flow_details`              |
| 7 | Interception          | `set_intercept_rules`           |
| 8 | Interception          | `get_intercepted_requests`      |
| 9 | Interception          | `forward_request`               |
|10 | Interception          | `drop_request`                  |
|11 | Proxy Control         | `set_proxy_intercept_state`     |
|12 | Proxy Control         | `get_proxy_status`              |
|13 | Proxy Control         | `replay_request`                |
|14 | Analysis              | `extract_json_fields`           |
|15 | Analysis              | `analyze_protection`            |
|16 | Annotation            | `add_log_note`                  |
|17 | Raw Wire Format       | `get_raw_http_message`          |
|18 | Configuration         | `get_config`                    |
|19 | Configuration         | `set_config`                    |
|20 | Encoding / Utility    | `url_encode`                    |
|21 | Encoding / Utility    | `url_decode`                    |
|22 | Encoding / Utility    | `base64_encode`                 |
|23 | Encoding / Utility    | `base64_decode`                 |
|24 | Encoding / Utility    | `generate_random_string`        |

---

## File and Directory Structure

```
mitmproxy-mcp/
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
│
├── migrations/
│   └── 001_initial.sql          # DDL for all tables; idempotent (IF NOT EXISTS)
│
└── src/
    └── mitmproxy_mcp/
        ├── __init__.py          # entry point: asyncio.run(main()) or threading start
        ├── main.py              # startup sequence, thread wiring, signal handling
        ├── app_state.py         # AppState dataclass
        ├── config.py            # env var → Settings (pydantic-settings or os.environ)
        ├── addon.py             # mitmproxy LoggingAddon — all hooks
        ├── db.py                # psycopg3 pool, migration runner, all CRUD functions
        ├── db_writer.py         # Thread 3: batch queue drain loop
        ├── mcp_server.py        # all 24 MCP tool definitions
        ├── queue_types.py       # HttpLogEntry, WsLogEntry typed dataclasses
        ├── json_utils.py        # JSON structure preview + JSONPath parser
        └── protection.py        # bot protection fingerprinting + JS analysis
```

---

## Startup Sequence (`main.py`)

```
1.  Load Settings from environment variables
2.  Construct AppState (logging_active.set() if logging default on)
3.  Initialise DB connection pool (psycopg_pool.ConnectionPool)
4.  Run migrations (execute migrations/001_initial.sql)
5.  Create threading.Queue(maxsize=QUEUE_MAXSIZE)
6.  Assign queue reference to AppState
7.  Start Thread 3 (DB writer) as daemon thread
8.  Construct LoggingAddon(app_state, queue)
9.  Start Thread 1 (mitmproxy) as daemon thread
     — Thread 1 captures asyncio.get_event_loop() into app_state.mitmproxy_loop
10. Register SIGTERM / SIGINT handlers (set stop event, call master.shutdown())
11. Build MCP server, register all 24 tools (tools receive app_state via closure)
12. mcp.run(transport="stdio")  ← blocks main thread until stdin closes
13. On exit: stop event set → join DB writer (5s timeout) → close DB pool
```

---

## Dependencies

```toml
[project]
requires-python = ">=3.12"

[project.dependencies]
mitmproxy       = ">=10.3"
mcp             = {version = ">=1.0", extras = ["cli"]}
psycopg         = {version = ">=3.1", extras = ["binary"]}
psycopg-pool    = ">=3.2"
httpx           = {version = ">=0.27", extras = ["http2"]}
pydantic        = ">=2.0"
```

---

## Key Design Decisions

| Decision | Choice | Reason |
|---|---|---|
| Control plane | MCP only (stdio) | No REST API surface to secure or maintain |
| MCP transport | stdio | Simple; agent connects via `docker exec -i` |
| Threading | Two-thread + writer | Avoids asyncio loop sharing complexity; proxy perf unaffected |
| Bodies | No size cap, BYTEA | Store everything; AI tools handle truncation at display time |
| AI truncation | 2000-byte threshold, JSON structure preview | Prevents token explosion without data loss |
| DB driver | psycopg3 (sync) | Matches two-thread model; simpler than asyncio driver in sync context |
| Interception signalling | asyncio.run_coroutine_threadsafe | Only official Python mechanism for cross-thread asyncio signalling |
| Queue full policy | block 50ms then drop | Absorbs DB hiccups; never stalls proxy under sustained overload |
| WebSocket HTTP linkage | http_log_id nullable | Handles race between HTTP upgrade insert and first WS frame |
| Body encoding in API | BYTEA → auto UTF-8/base64 | Transparent binary handling; no encoding assumptions at storage layer |

---

## Open Risks

1. **True intercept hold vs. flow:** `set_proxy_intercept_state(intercept=false)` stops
   holding requests but traffic still flows. This is intentional. A "pause all traffic"
   mode (blocking the TCP accept loop) is a potential v2 feature.

2. **Concurrent intercepts at scale:** If 50 requests match intercept rules simultaneously,
   all 50 suspend in mitmproxy's event loop. The event loop still runs (each suspension is
   `await event.wait()`, not a block) but memory grows proportionally. Mitigate with a
   configurable `max_concurrent_intercepts` (default 20) that auto-forwards overflow entries.

3. **`send_http_request` log_id timing:** Synchronous DB insert on the `send_http_request`
   path adds latency (~2–5ms). Acceptable for a tool call; not acceptable on the hot proxy path.

4. **Regex full-table-scans on body fields:** `~*` on BYTEA-cast-to-TEXT has no index support.
   Acceptable for dev/pentest scale. Document a `since` timestamp filter parameter to scope scans.

5. **mitmproxy version pinning:** The addon API changed significantly between v9 and v10.
   Pin exact minor version in pyproject.toml and document minimum supported version.

6. **stdio MCP + Docker:** The agent must run `docker exec -i <container> python -m
   mitmproxy_mcp.main` (or equivalent). The CA cert must be separately extracted from the
   `mitmproxy_certs` volume and trusted by the agent's HTTP client for HTTPS interception.
