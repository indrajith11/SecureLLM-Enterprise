# MCP interop (Wave 6.3 server + 6.4 client)

**Status: shipped in v4.4.0 · server + client + tests complete · off by
default, fails closed.** SecureLLM speaks the [Model Context Protocol](https://modelcontextprotocol.io)
(JSON-RPC 2.0 over stdio, newline-delimited frames) in both directions —
and both directions are **clients of the governed path, never a bypass**.

## 6.3 MCP server — governed answers as MCP tools

`python -m src.mcp.server` exposes two tools to any MCP host (Claude
Desktop, IDEs):

- `securellm_chat` — one governed round-trip: `channel="mcp"` + the
  caller handle in `external_user` land in the L7 audit chain; answers
  pass L1 auth → L2 rate limit → L2b input firewall → CIA/RBAC → L5 →
  L6 DLP exactly like web requests.
- `securellm_health` — public posture payload (status, version, backend
  reachability).

Protocol surface: `initialize` (echoes protocol version, capabilities,
serverInfo), `notifications/initialized`, `ping`, `tools/list` (with
input schemas), `tools/call`. Failures map to tool-level `isError` with
operator-visible text: kill-switch 503, rate-limit 429, governance denial,
backend unreachable — the protocol frame never crashes.

Env: `mcp.enabled: true` + `MCP_SERVICE_USER` / `MCP_SERVICE_PASSWORD`
(least-privilege identity) + optional `SECURELLM_API_URL`. Diagnostics go
to **stderr only** — stdout carries nothing but protocol frames.

## 6.4 MCP client — external servers under governance

`src/mcp/client.py` calls EXTERNAL MCP servers as fenced tools:

| Concern | Control |
|---|---|
| Untrusted servers | A server exists only if configured under `mcp.client.servers` (command from CONFIG, never from model output) |
| Tool allowlist | Only namespaced `mcp_<server>_<tool>` entries in `mcp.client.allowed_tools` are callable — deny-closed default |
| Role gating | Optional `mcp.client.tool_roles` restricts tools to roles, same semantics as L3 RBAC |
| Secrets fencing | Subprocess env is minimal (PATH + PYTHONUNBUFFERED) — host secrets never leak to external servers (test-pinned) |
| Hang guard | Every frame has a deadline; a hung server surfaces as `McpClientError` (reader-thread + queue), never freezes the pipeline |
| Naming | External tools can never shadow built-ins (namespace prefix) |

```yaml
mcp:
  client:
    servers: {weather: {command: ["python", "path/to/weather_mcp.py"]}}
    allowed_tools: ["mcp_weather_get_forecast"]
    tool_roles: {mcp_weather_get_forecast: ["Analyst", "Admin"]}
```

`python -m src.mcp.client --server weather` lists the server's tools with
`*` marking allow-listed ones (discovery is harmless; calls stay gated).
This module is the L5 wiring seam: chat-time tool selection can call
`run_mcp_tool(role, server, tool, args)` behind the same RBAC gate that
guards data tools.

## Verification

- `tests/test_mcp_server.py` (14): fail-closed settings, protocol shapes,
  governed attribution, 503/429 mapping, -32601/-32602/-32700 handling,
  stdio loop resilience.
- `tests/test_mcp_client.py` (9): real-subprocess transport against a stub
  server, deny-closed gates (server / allowlist / role), catalog marking,
  **secrets-fencing probe** (host secrets absent from the child env), and
  the hang guard (a server that stops answering is killed by deadline).
