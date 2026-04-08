# mitmproxy-mcp

An MCP (Model Context Protocol) server that wraps mitmproxy, giving AI agents the ability to intercept, inspect, modify, and replay HTTP/WebSocket traffic through natural language.

> **Status:** Early development. Not all features have been fully tested. See [ROADMAP.md](ROADMAP.md) for planned work.

## What it does

Point any HTTP client at the proxy and let an AI agent (e.g. Claude Code) observe and manipulate the traffic in real time. All requests are logged to PostgreSQL for querying and analysis.

## Features

### Proxy & Traffic Capture
- Transparent HTTP/HTTPS interception via mitmproxy
- WebSocket traffic capture
- All traffic persisted to PostgreSQL with full request/response details
- Adminer web UI for direct database access

### MCP Tools (25 tools)

| Category | Tools |
|----------|-------|
| **HTTP** | `send_http_request`, `replay_request` |
| **History** | `get_proxy_http_history`, `get_proxy_http_history_regex`, `get_proxy_websocket_history`, `get_proxy_websocket_history_regex`, `get_flow_details`, `get_raw_http_message` |
| **Intercept** | `set_intercept_rules`, `get_intercepted_requests`, `forward_request`, `drop_request`, `set_proxy_intercept_state` |
| **Analysis** | `analyze_protection`, `extract_json_fields`, `add_log_note` |
| **Config** | `get_config`, `set_config`, `get_proxy_status` |
| **Utilities** | `url_encode`, `url_decode`, `base64_encode`, `base64_decode`, `generate_random_string` |

## Quick Start

### Prerequisites
- Docker and Docker Compose v2
- Claude Code CLI

### Start the stack

```bash
docker compose up -d
```

This starts 3 containers:

| Service | Port | Description |
|---------|------|-------------|
| app | 8080 | mitmproxy + MCP server |
| postgres | 5432 | PostgreSQL 16 |
| adminer | 8082 | Database web UI |

### Connect to Claude Code

```bash
claude mcp add --transport stdio --scope project mitmproxy-mcp -- \
  docker exec -i mitmproxy-mcp-app-1 python -m mitmproxy_mcp
```

Then restart Claude Code in the `mitmproxy-mcp/` directory.

### Verify

```bash
# Check containers
docker compose ps

# Test proxy
curl -x http://localhost:8080 http://httpbin.org/get

# Check MCP tools
claude mcp list
```

### HTTPS Interception

```bash
# Extract CA cert
docker cp mitmproxy-mcp-app-1:/root/.mitmproxy/mitmproxy-ca-cert.pem .

# Use with curl
curl --cacert mitmproxy-ca-cert.pem -x http://localhost:8080 https://example.com
```

## Architecture

```
Client --> mitmproxy (port 8080) --> Target Server
               |
               v
          MCP Server <--> Claude Code
               |
               v
          PostgreSQL (port 5432)
```

## Tech Stack

- **Python 3.12+**
- **mitmproxy** - HTTP/HTTPS proxy
- **MCP SDK** - Model Context Protocol server
- **PostgreSQL 16** - Traffic storage
- **psycopg3** - Async PostgreSQL driver
- **httpx** - HTTP client for replaying requests

## License

MIT
