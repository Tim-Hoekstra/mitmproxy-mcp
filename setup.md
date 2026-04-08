# mitmproxy-mcp Setup

## Prerequisites

- Docker and Docker Compose v2
- Claude Code CLI

## Start the stack

```bash
docker compose up -d
```

This starts 3 containers:

| Service | Port | Description |
|---------|------|-------------|
| app | 8080 | mitmproxy proxy + MCP server |
| postgres | 5432 | PostgreSQL 16 database |
| adminer | 8082 | Database web UI |

## Connect to Claude Code

```bash
claude mcp add --transport stdio --scope project mitmproxy-mcp -- docker exec -i mitmproxy-mcp-app-1 python -m mitmproxy_mcp
```

Then restart Claude Code in the `mitmproxy-mcp/` directory.

## Verify

```bash
# Check all containers are running
docker compose ps

# Check proxy works
curl -x http://localhost:8080 http://httpbin.org/get

# Check database UI
open http://localhost:8082
# Login: System=PostgreSQL, Server=postgres, User=mitmuser, Pass=mitmpass, DB=mitmdb

# Check MCP tools are visible
claude mcp list
```

## Configure clients to use the proxy

Point your HTTP client at `http://localhost:8080`.

For HTTPS interception, trust the mitmproxy CA cert:

```bash
# Extract the CA cert from the container
docker cp mitmproxy-mcp-app-1:/root/.mitmproxy/mitmproxy-ca-cert.pem .

# For curl
curl --cacert mitmproxy-ca-cert.pem -x http://localhost:8080 https://example.com

# For system-wide trust (Linux)
sudo cp mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

## Stop

```bash
docker compose down
```

Data persists in Docker volumes (`pgdata`, `mitmproxy_certs`). To wipe everything:

```bash
docker compose down -v
```
