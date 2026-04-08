# Roadmap

## Current Status

The core proxy, MCP server, and database pipeline are functional. Not all MCP tool endpoints have been fully tested end-to-end.

## In Progress

### Endpoint Testing
Full end-to-end testing of all 25 MCP tools:

- [ ] `send_http_request`
- [ ] `get_proxy_http_history`
- [ ] `get_proxy_http_history_regex`
- [ ] `get_proxy_websocket_history`
- [ ] `get_proxy_websocket_history_regex`
- [ ] `get_flow_details`
- [ ] `get_raw_http_message`
- [ ] `set_intercept_rules`
- [ ] `get_intercepted_requests`
- [ ] `forward_request`
- [ ] `drop_request`
- [ ] `set_proxy_intercept_state`
- [ ] `replay_request`
- [ ] `extract_json_fields`
- [ ] `analyze_protection`
- [ ] `add_log_note`
- [ ] `get_config`
- [ ] `set_config`
- [ ] `get_proxy_status`
- [ ] `url_encode`
- [ ] `url_decode`
- [ ] `base64_encode`
- [ ] `base64_decode`
- [ ] `generate_random_string`

## Planned

### LangSmith Integration
- Integrate LangSmith for observability and tracing of MCP tool calls
- Track token usage, latency, and tool invocation patterns
- Enable evaluation and debugging of agent-proxy interactions

### Testing
- Unit tests for core modules
- Integration tests against live proxy + database
- CI pipeline for automated test runs

### Features
- Authentication support (API keys, OAuth tokens)
- Traffic filtering and search improvements
- Export functionality (HAR, cURL)
- Rate limiting and request throttling
- Multi-proxy support
