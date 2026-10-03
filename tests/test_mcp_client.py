"""Wave 6.4 - MCP client: calling EXTERNAL MCP servers under governance.

Pinned guarantees:
  - namespacing: external tools are mcp_<server>_<tool> - an external
    server can never shadow a built-in capability;
  - fail-closed gating: an unconfigured server raises McpDenied, a tool
    missing from mcp.client.allowed_tools raises McpDenied, a role not in
    mcp.client.tool_roles raises McpDenied;
  - the subprocess environment is minimal (PATH + PYTHONUNBUFFERED only)
    - no secrets of the host process leak to external servers;
  - transport: real subprocess speaking newline-delimited JSON-RPC against
    a stub MCP server (no layer mocked), with a hang guard (timeout).
"""
import json
import sys
import time
from pathlib import Path

import pytest

from src.mcp import client as mcp_client

STUB = str(Path(__file__).parent / "stub_mcp_server.py")


@pytest.fixture()
def cfg(monkeypatch):
    """Config with one stub server, one allowlisted tool, role gate."""
    def _app_config():
        return {"mcp": {"client": {
            "servers": {"calc": {"command": [sys.executable, STUB]}},
            "allowed_tools": ["mcp_calc_add"],
            "tool_roles": {"mcp_calc_add": ["Analyst", "Admin"]},
            "timeout_s": 10}}}
    monkeypatch.setattr(mcp_client, "app_config", _app_config)


# ---------- transport against a real stub server --------------------------------
def test_initialize_list_and_call_against_stub():
    c = mcp_client.McpStdioClient("calc", [sys.executable, STUB], timeout=10)
    try:
        assert c.protocol_version == "2024-11-05"
        tools = c.list_tools()
        assert {"name": "add", "description": "Add two numbers"} == {
            "name": tools[0]["name"], "description": tools[0]["description"]}
        res = c.call_tool("add", {"a": 2, "b": 3})
        assert res["content"][0]["text"] == "5"
    finally:
        c.close()


def test_dead_command_raises_mcp_client_error():
    with pytest.raises(mcp_client.McpClientError, match="cannot spawn"):
        mcp_client.McpStdioClient("nope", ["/nonexistent/binary-xyz"])


# ---------- governance gates (fail closed) ---------------------------------------
def test_unconfigured_server_denied(cfg):
    with pytest.raises(mcp_client.McpDenied, match="not configured"):
        mcp_client.run_mcp_tool("Admin", "unknown-server", "add", {})


def test_unallowlisted_tool_denied(cfg):
    with pytest.raises(mcp_client.McpDenied, match="allowlist"):
        mcp_client.run_mcp_tool("Admin", "calc", "shell", {})


def test_role_gate_denied(cfg):
    with pytest.raises(mcp_client.McpDenied, match="may not call"):
        mcp_client.run_mcp_tool("Viewer", "calc", "add", {})


def test_allowlisted_tool_runs_fenced(cfg):
    res = mcp_client.run_mcp_tool("Analyst", "calc", "add",
                                  {"a": 20, "b": 22})
    assert res["content"][0]["text"] == "42"


def test_catalog_marks_allowlist_state(cfg):
    items = mcp_client.catalog()
    by_tool = {i["tool"]: i for i in items}
    assert by_tool["mcp_calc_add"]["allowlisted"] is True
    assert by_tool["mcp_calc_echo"]["allowlisted"] is False
    assert by_tool["mcp_calc_add"]["server"] == "calc"


# ---------- subprocess environment fencing ---------------------------------------
def test_stub_sees_no_host_secrets(monkeypatch):
    """The fenced env must NOT carry host secrets to external servers."""
    monkeypatch.setenv("SECURELLM_JWT_SECRET", "super-secret-value")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "stub-bot-token")
    c = mcp_client.McpStdioClient("calc", [sys.executable, STUB], timeout=10)
    try:
        res = c.call_tool("env_probe", {})
        env = json.loads(res["content"][0]["text"])
        assert "super-secret-value" not in json.dumps(env)
        assert "stub-bot-token" not in json.dumps(env)
        assert env.get("PYTHONUNBUFFERED") == "1"   # minimal env present
    finally:
        c.close()


# ---------- hang guard ------------------------------------------------------------
def test_timeout_on_hung_server(cfg):
    c = mcp_client.McpStdioClient(
        "calc", [sys.executable, STUB, "--hang"], timeout=1.0)
    try:
        t0 = time.time()
        with pytest.raises(mcp_client.McpClientError, match="timed out"):
            c.list_tools()
        assert time.time() - t0 < 6
    finally:
        c.close()
