"""Wave 6.3 - MCP server: governed answers as MCP tools (stdio JSON-RPC).

Pinned guarantees:
  - fail-closed startup: disabled feature or missing service credentials
    refuse to start;
  - the protocol speaks enough MCP for real clients: initialize (echo
    protocol version, capabilities, serverInfo), notifications (no
    response), ping, tools/list (schemas included), tools/call;
  - securellm_chat calls the governed API with channel="mcp" and the
    caller handle in external_user - the L1-L7 pipeline stays the only
    path to a model, and the audit chain attributes the human;
  - backend failures map to tool-level isError with operator-visible
    text (kill switch 503, rate limit 429, governance denial) instead
    of protocol crashes.
"""
import json

import pytest

from src.mcp import server as mcp_server


# ---------- fail-closed configuration -----------------------------------------
def test_disabled_feature_refuses_to_start(monkeypatch):
    monkeypatch.setattr(mcp_server, "app_config",
                        lambda: {"mcp": {"enabled": False}})
    with pytest.raises(mcp_server.McpConfigError, match="disabled"):
        mcp_server.load_settings()


def test_missing_credentials_refuse_to_start(monkeypatch):
    monkeypatch.setattr(mcp_server, "app_config",
                        lambda: {"mcp": {"enabled": True}})
    monkeypatch.delenv("MCP_SERVICE_USER", raising=False)
    monkeypatch.delenv("MCP_SERVICE_PASSWORD", raising=False)
    with pytest.raises(mcp_server.McpConfigError, match="MCP_SERVICE_USER"):
        mcp_server.load_settings()


# ---------- protocol dispatch (pure seam) ---------------------------------------
class _FakeClient:
    def __init__(self):
        self.calls = []

    def chat(self, question, caller):
        self.calls.append(("chat", question, caller))
        return {"text": "A governed answer.", "isError": False}

    def health(self):
        self.calls.append(("health",))
        return {"text": '{"status": "healthy"}', "isError": False}


@pytest.fixture()
def fc():
    return _FakeClient()


def test_initialize_echoes_protocol_version_and_info(fc):
    resp = mcp_server.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}}, fc)
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    assert resp["result"]["serverInfo"]["name"] == "securellm-enterprise"
    assert "tools" in resp["result"]["capabilities"]


def test_notifications_yield_no_response(fc):
    assert mcp_server.dispatch(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}, fc) is None


def test_ping(fc):
    assert mcp_server.dispatch(
        {"jsonrpc": "2.0", "id": 2, "method": "ping"}, fc) == {
        "jsonrpc": "2.0", "id": 2, "result": {}}


def test_tools_list_exposes_schemas(fc):
    resp = mcp_server.dispatch(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, fc)
    names = [t["name"] for t in resp["result"]["tools"]]
    assert names == ["securellm_chat", "securellm_health"]
    schema = resp["result"]["tools"][0]["inputSchema"]
    assert "question" in schema["properties"]
    assert schema["properties"]["question"]["maxLength"] == 4000


def test_tools_call_chat_goes_governed(fc):
    resp = mcp_server.dispatch(
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "securellm_chat",
                    "arguments": {"question": "What is the leave policy?",
                                  "caller": "claude-desktop"}}}, fc)
    assert fc.calls == [("chat", "What is the leave policy?",
                         "claude-desktop")]
    assert resp["result"]["isError"] is False
    assert resp["result"]["content"][0]["text"] == "A governed answer."


def test_tools_call_health(fc):
    resp = mcp_server.dispatch(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "securellm_health", "arguments": {}}}, fc)
    assert resp["result"]["isError"] is False
    assert "healthy" in resp["result"]["content"][0]["text"]


def test_unknown_tool_is_invalid_params(fc):
    resp = mcp_server.dispatch(
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
         "params": {"name": "rm_rf", "arguments": {}}}, fc)
    assert resp["error"]["code"] == -32602


def test_unknown_method(fc):
    resp = mcp_server.dispatch(
        {"jsonrpc": "2.0", "id": 7, "method": "resources/list"}, fc)
    assert resp["error"]["code"] == -32601


def test_empty_question_is_invalid_params(fc):
    resp = mcp_server.dispatch(
        {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
         "params": {"name": "securellm_chat", "arguments": {"question": "  "}}},
        fc)
    assert resp["error"]["code"] == -32602


# ---------- governed-client failure mapping -------------------------------------
def test_chat_503_maps_to_visible_tool_error(monkeypatch):
    class _C:
        def chat(self, q, caller):
            return {"text": "AI features are temporarily disabled by the "
                            "operator.", "isError": True}
    resp = mcp_server.dispatch(
        {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
         "params": {"name": "securellm_chat",
                    "arguments": {"question": "hi"}}}, _C())
    assert resp["result"]["isError"] is True
    assert "temporarily disabled" in resp["result"]["content"][0]["text"]


def test_real_governed_client_maps_status_codes(monkeypatch):
    # GovernedClient.chat with a stub httpx transport (no network)
    import httpx
    st = {"api_url": "http://stub", "user": "mcp_bridge",
          "password": "pw", "cfg": {}}
    client = mcp_server.GovernedClient(st)

    def handler(request):
        if request.url.path == "/api/login":
            return httpx.Response(200, json={
                "access_token": "t", "expires_in": 3600})
        if request.url.path == "/api/chat":
            _StubState.last = json.loads(request.content.decode())
            return httpx.Response(503, json={"detail": "disabled"})
        return httpx.Response(404)

    class _StubState:
        last = {}

    transport = httpx.MockTransport(handler)
    tclient = httpx.Client(transport=transport)
    # GovernedClient uses module-level httpx.post/httpx.get; patch them
    monkeypatch.setattr(
        mcp_server.httpx, "post",
        lambda url, **kw: tclient.post(url, **kw))
    monkeypatch.setattr(
        mcp_server.httpx, "get",
        lambda url, **kw: tclient.get(url, **kw))
    out = client.chat("hello", "u1")
    assert out["isError"] is True
    assert "temporarily disabled" in out["text"]
    assert _StubState.last["channel"] == "mcp"      # audit attribution
    assert _StubState.last["external_user"] == "u1"


def test_stdio_loop_serves_frames_then_exits(monkeypatch, fc):
    monkeypatch.setattr(mcp_server, "load_settings",
                        lambda: {"api_url": "http://stub", "user": "u",
                                 "password": "p"})
    monkeypatch.setattr(mcp_server, "GovernedClient", lambda s: fc)
    stdin = iter([json.dumps({"jsonrpc": "2.0", "id": 1,
                              "method": "tools/list"}),
                  "not-json", "\n"])
    import io
    out = io.StringIO()
    mcp_server.serve(stdin, out)
    lines = [json.loads(l) for l in out.getvalue().splitlines()]
    assert len(lines) == 2                       # tools/list + parse error
    assert lines[0]["result"]["tools"][0]["name"] == "securellm_chat"
    assert lines[1]["error"]["code"] == -32700   # parse error, loop lived
