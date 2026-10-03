"""Wave 6.3 - MCP server: SecureLLM's governed answers as Model Context
Protocol tools (JSON-RPC 2.0 over stdio, newline-delimited).

SECURITY MODEL (identical philosophy to the Telegram bridge - a client of
the governed API, never a bypass):
  - tools/call for securellm_chat performs ONE POST /api/chat with
    channel="mcp" and the caller handle in external_user: the request
    crosses the same L1-L7 pipeline (auth, rate limit, input firewall,
    CIA/RBAC, model, DLP, audit chain) as any web request.
  - The server authenticates as ONE configured service identity
    (MCP_SERVICE_USER / MCP_SERVICE_PASSWORD, env-only).
  - enabled=false (default) or missing credentials -> refuse to start
    (fail closed). All diagnostics go to STDERR; stdout carries only
    protocol frames.

Protocol subset (enough for Claude Desktop / any MCP client):
  initialize | notifications/initialized | ping | tools/list | tools/call

Run:  python -m src.mcp.server        (stdio; a host process spawns it)
"""
from __future__ import annotations

import json
import os
import sys

import httpx

from src.common.paths import app_config, get_nested

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "securellm-enterprise", "version": "4.8.2"}


class McpConfigError(RuntimeError):
    """Fail-closed startup."""


def load_settings() -> dict:
    cfg = app_config()
    mcp = get_nested(cfg, "mcp", {}) or {}
    if not get_nested(mcp, "enabled", False):
        raise McpConfigError(
            "mcp server disabled (mcp.enabled != true) - enable explicitly")
    api_url = os.environ.get("SECURELLM_API_URL", "") or get_nested(
        mcp, "api_url", "http://localhost:8000")
    user = os.environ.get("MCP_SERVICE_USER", "")
    password = os.environ.get("MCP_SERVICE_PASSWORD", "")
    if not (user and password):
        raise McpConfigError(
            "MCP_SERVICE_USER / MCP_SERVICE_PASSWORD missing - refusing "
            "to start (fail closed)")
    return {"api_url": api_url.rstrip("/"), "user": user,
            "password": password, "cfg": mcp}


TOOLS = [
    {
        "name": "securellm_chat",
        "description": (
            "Ask the SecureLLM-Enterprise company assistant a question. "
            "The answer passes the full governance pipeline: role-scoped "
            "access (CIA), input firewall, retrieval, output DLP and a "
            "tamper-evident audit record."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "question": {"type": "string",
                             "maxLength": 4000,
                             "description": "The work question to ask."},
                "caller": {"type": "string", "maxLength": 64,
                           "description": "Handle of the human asking, "
                                          "recorded in the audit trail."},
            },
            "required": ["question"],
        },
    },
    {
        "name": "securellm_health",
        "description": "Liveness + backend posture of SecureLLM-Enterprise "
                       "(public /health payload: status, version, model "
                       "backend reachability).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class GovernedClient:
    """Minimal HTTP client for the governed API with JWT caching."""

    def __init__(self, settings: dict):
        self.api = settings["api_url"]
        self.user = settings["user"]
        self.password = settings["password"]
        self._token = ""
        self._exp = 0.0

    def _login(self) -> str:
        if self._token and self._exp > __import__("time").time() + 60:
            return self._token
        r = httpx.post(f"{self.api}/api/login",
                       json={"username": self.user,
                             "password": self.password}, timeout=30)
        if r.status_code != 200:
            raise McpConfigError(
                f"service login failed ({r.status_code})")
        body = r.json()
        self._token = body["access_token"]
        self._exp = __import__("time").time() + float(
            body.get("expires_in", 3600))
        return self._token

    def chat(self, question: str, caller: str) -> dict:
        r = httpx.post(
            f"{self.api}/api/chat",
            headers={"Authorization": f"Bearer {self._login()}"},
            json={"message": question[:4000], "channel": "mcp",
                  "external_user": caller[:64]},
            timeout=180)
        if r.status_code == 503:
            return {"text": "AI features are temporarily disabled by the "
                            "operator.", "isError": True}
        if r.status_code == 429:
            return {"text": "Rate limit exceeded - retry shortly.",
                    "isError": True}
        if r.status_code != 200:
            detail = ""
            try:
                detail = r.json().get("detail", "")
            except ValueError:
                pass
            return {"text": f"Request denied by governance: {detail}"
                    if detail else "Request could not be completed.",
                    "isError": True}
        body = r.json()
        return {"text": body.get("response", "(empty answer)"),
                "isError": False}

    def health(self) -> dict:
        r = httpx.get(f"{self.api}/health", timeout=10)
        b = r.json() if r.status_code == 200 else {}
        return {"text": json.dumps({
            "status": b.get("status", "unknown"),
            "version": b.get("version"),
            "model_backend": b.get("model_backend"),
            "ollama_reachable": b.get("ollama_reachable"),
            "colibri_reachable": b.get("colibri_reachable"),
        }), "isError": r.status_code != 200}


def dispatch(msg: dict, client: GovernedClient) -> dict | None:
    """Pure JSON-RPC dispatch (unit-test seam). None = no response needed."""
    method = msg.get("method", "")
    mid = msg.get("id")
    is_notification = mid is None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": msg.get("params", {}).get(
                "protocolVersion", PROTOCOL_VERSION),
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO}}
    if method.startswith("notifications/"):
        return None                       # initialized, cancelled, ...
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params", {}) or {}
        name = params.get("name", "")
        args = params.get("arguments", {}) or {}
        try:
            if name == "securellm_chat":
                q = args.get("question")
                if not isinstance(q, str) or not q.strip():
                    return {"jsonrpc": "2.0", "id": mid, "error": {
                        "code": -32602,
                        "message": "invalid arguments: question is "
                                   "required (non-empty string)"}}
                out = client.chat(q, str(args.get("caller", "mcp-client")))
            elif name == "securellm_health":
                out = client.health()
            else:
                return {"jsonrpc": "2.0", "id": mid, "error": {
                    "code": -32602,
                    "message": f"Unknown tool: {name}"}}
        except (McpConfigError, httpx.HTTPError) as e:
            out = {"text": f"SecureLLM backend unavailable: {e}",
                   "isError": True}
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": out["text"]}],
            "isError": out["isError"]}}
    if is_notification:
        return None
    return {"jsonrpc": "2.0", "id": mid, "error": {
        "code": -32601, "message": f"Method not found: {method}"}}


def serve(stdin=sys.stdin, stdout=sys.stdout) -> None:
    """stdio loop: newline-delimited JSON-RPC in, responses out."""
    settings = load_settings()
    client = GovernedClient(settings)
    print(f"[mcp-server] up: api={settings['api_url']}", file=sys.stderr)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {
                "code": -32700, "message": "Parse error"}}
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
            continue
        try:
            resp = dispatch(msg, client)
        except Exception as e:            # never kill the loop
            resp = {"jsonrpc": "2.0", "id": msg.get("id"), "error": {
                "code": -32603, "message": f"Internal error: {e}"}}
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
    print("[mcp-server] stdin closed - exiting", file=sys.stderr)


def main() -> int:                         # pragma: no cover - live entry
    try:
        serve()
    except McpConfigError as e:
        print(f"[mcp-server] REFUSING TO START: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
