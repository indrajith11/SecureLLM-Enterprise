"""Wave 6.4 - MCP client: SecureLLM calling EXTERNAL MCP servers.

SECURITY MODEL (the mirror image of our server - we become the client):
  - External MCP servers are UNTRUSTED by default. A server is usable only
    if its name is listed in mcp.client.servers (config) AND the specific
    tool is listed in mcp.client.allowed_tools - both fail closed.
  - Tool names are namespaced mcp_<server>_<tool> so an external tool can
    never shadow a built-in capability.
  - Role gating: each allowed tool may optionally restrict roles
    (mcp.client.tool_roles: {tool: [roles...]}); the caller context is
    checked the same way L3 RBAC checks data tools.
  - Process fencing: the server command comes from CONFIG (not from any
    model output, ever); a fresh subprocess per client instance, killed on
    close. Environment passed to the subprocess is minimal by default.
  - Timeouts on every frame; a hung server is killed, not waited on.

This module is the L5 wiring seam: chat-time tool selection can call
run_mcp_tool(user_ctx, server, tool, arguments) after the same RBAC gate
that guards data tools. Nothing here talks to a model directly.

Run (smoke):  python -m src.mcp.client --server <name>  (lists tools)
"""
from __future__ import annotations

import itertools
import json
import os
import queue
import subprocess
import sys
import threading
import time

from src.common.paths import app_config, get_nested


class McpClientError(RuntimeError):
    """Transport or protocol failure with an external MCP server."""


class McpDenied(PermissionError):
    """The requested server/tool is not allow-listed (fail closed)."""


class McpStdioClient:
    """One external MCP server over stdio (newline-delimited JSON-RPC)."""

    def __init__(self, name: str, command: list[str], timeout: float = 15.0):
        self.name = name
        self.timeout = timeout
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "PYTHONUNBUFFERED": "1"}
        try:
            self.proc = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1)
        except OSError as e:
            raise McpClientError(
                f"cannot spawn MCP server {name!r}: {e}") from e
        # Timeout-aware reads: a hung server must surface as McpClientError,
        # not freeze the governance pipeline. A daemon reader thread pushes
        # frames into a bounded queue; _recv() dequeues with a deadline.
        self._frames: queue.Queue = queue.Queue()
        self._rpc_deadline = 0.0
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self.protocol_version = self._initialize()

    # ------------------------------------------------- frame helpers
    def _send(self, payload: dict) -> None:
        assert self.proc.stdin
        with self._lock:
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()

    def _read_loop(self) -> None:
        assert self.proc.stdout
        for line in self.proc.stdout:      # ends when the pipe closes
            self._frames.put(line)

    def _recv(self) -> dict:
        remaining = self.timeout - (time.time() - self._rpc_deadline)
        try:
            line = self._frames.get(timeout=max(0.05, remaining))
        except queue.Empty as e:
            raise McpClientError(
                f"MCP server {self.name!r} timed out (no frame within "
                f"{self.timeout}s)") from e
        if not line:
            raise McpClientError(
                f"MCP server {self.name!r} closed the pipe")
        try:
            return json.loads(line)
        except json.JSONDecodeError as e:
            raise McpClientError(
                f"MCP server {self.name!r} sent a non-JSON frame") from e

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        mid = next(self._ids)
        self._send({"jsonrpc": "2.0", "id": mid, "method": method,
                    "params": params or {}})
        self._rpc_deadline = time.time()
        while True:
            if time.time() - self._rpc_deadline > self.timeout:
                raise McpClientError(
                    f"MCP server {self.name!r} timed out on {method}")
            msg = self._recv()
            if msg.get("id") == mid:
                if "error" in msg:
                    raise McpClientError(
                        f"{method} -> {msg['error'].get('message')}")
                return msg.get("result", {})

    # ------------------------------------------------- MCP lifecycle
    def _initialize(self) -> str:
        res = self._rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "securellm-enterprise",
                           "version": "4.8.0"}})
        self._send({"jsonrpc": "2.0",
                    "method": "notifications/initialized"})
        return str(res.get("protocolVersion", ""))

    def list_tools(self) -> list[dict]:
        return self._rpc("tools/list").get("tools", [])

    def call_tool(self, tool: str, arguments: dict) -> dict:
        return self._rpc("tools/call",
                         {"name": tool, "arguments": arguments})

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


# ------------------------------------------------------------------ governance
def _client_settings() -> dict:
    cfg = app_config()
    cl = get_nested(cfg, "mcp.client", {}) or {}
    servers = get_nested(cl, "servers", {}) or {}
    return {
        "servers": {str(k): v for k, v in servers.items()},
        "allowed": set(get_nested(cl, "allowed_tools", []) or []),
        "tool_roles": get_nested(cl, "tool_roles", {}) or {},
        "timeout": float(get_nested(cl, "timeout_s", 15)),
    }


def _namespaced(server: str, tool: str) -> str:
    return f"mcp_{server}_{tool}"


def run_mcp_tool(user_ctx_role: str, server: str, tool: str,
                 arguments: dict) -> dict:
    """Governed entry point: allowlist + role gate + fenced call.
    Returns the MCP tool result; raises McpDenied / McpClientError."""
    st = _client_settings()
    fq = _namespaced(server, tool)
    if server not in st["servers"]:
        raise McpDenied(f"MCP server {server!r} is not configured")
    if fq not in st["allowed"]:
        raise McpDenied(
            f"tool {fq!r} is not on the mcp allowlist (fail closed)")
    roles = st["tool_roles"].get(fq)
    if roles and user_ctx_role not in roles:
        raise McpDenied(
            f"role {user_ctx_role!r} may not call {fq!r}")
    cmd = st["servers"][server].get("command")
    if not (isinstance(cmd, list) and cmd):
        raise McpClientError(
            f"MCP server {server!r} has no command configured")
    client = McpStdioClient(server, cmd, timeout=st["timeout"])
    try:
        return client.call_tool(tool, arguments)
    finally:
        client.close()


def catalog() -> list[dict]:
    """Discover tools of every configured server (operator utility).
    Discovery is NOT invocation - listing is harmless; calls stay gated."""
    st = _client_settings()
    out = []
    for name, conf in st["servers"].items():
        cmd = conf.get("command")
        if not (isinstance(cmd, list) and cmd):
            continue
        try:
            client = McpStdioClient(name, cmd, timeout=st["timeout"])
            try:
                for t in client.list_tools():
                    out.append({"server": name,
                                "tool": _namespaced(name, t.get("name", "")),
                                "description": t.get("description", ""),
                                "allowlisted":
                                    _namespaced(name, t.get("name", ""))
                                    in st["allowed"]})
            finally:
                client.close()
        except McpClientError as e:
            out.append({"server": name, "tool": "", "description": f"ERR: {e}",
                        "allowlisted": False})
    return out


def main(argv: list[str]) -> int:          # pragma: no cover - smoke entry
    if len(argv) < 2 or argv[1] != "--server" or len(argv) < 3:
        print("usage: python -m src.mcp.client --server <name>",
              file=sys.stderr)
        return 2
    name = argv[2]
    st = _client_settings()
    if name not in st["servers"]:
        print(f"server {name!r} not configured (mcp.client.servers)",
              file=sys.stderr)
        return 2
    client = McpStdioClient(name, st["servers"][name]["command"],
                            timeout=st["timeout"])
    try:
        for t in client.list_tools():
            fq = _namespaced(name, t.get("name", ""))
            star = "*" if fq in st["allowed"] else " "
            print(f" {star} {fq:40s} {t.get('description', '')[:60]}")
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
