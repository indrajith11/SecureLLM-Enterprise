"""colibri backend integration (v4.3.0) - frontier MoE serving via
OpenAI-compatible API.

Pinned guarantees:
  - the wire module speaks coli serve's OpenAI contract (docs/api.md):
    GET /v1/models probe, POST /v1/chat/completions JSON + SSE, Bearer
    auth ONLY when a key is configured, reasoning_effort ONLY when the
    router asked for thinking;
  - HTTP 429 (colibri's designed admission-queue saturation) maps to
    ProviderUnavailable so the shared retry -> other-model -> visible-
    mock chain treats an overloaded 744B engine like an unreachable one;
  - MODEL_PROVIDER=colibri is explicit opt-in (never auto), unknown
    provider names fail CLOSED to mock, and every governed request
    degrades VISIBLY (CHAT-01 - no silent brain swap);
  - ollama behaviour is byte-for-byte unchanged (regression guard).

The stub server below is a real TCP HTTP server implementing coli
serve's wire shapes - no HTTP layer is mocked away.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from src.model import colibri_model, mock_model, ollama_model, provider

STUB_MODEL = "glm-5.2-colibri"


# ---------- coli serve stub (real HTTP on 127.0.0.1) -------------------------
class _StubColi(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    behavior = "ok"          # ok | 429 | empty | drop
    api_key = ""
    last_request: dict = {}
    last_auth: str | None = None

    def log_message(self, *args):  # silence test output
        pass

    def _guard_auth(self) -> bool:
        if not _StubColi.api_key:
            return True
        want = f"Bearer {_StubColi.api_key}"
        if self.headers.get("Authorization") != want:
            body = json.dumps(
                {"error": {"message": "invalid api key"}}).encode()
            self.send_response(401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return False
        return True

    def do_GET(self):
        if self.path != "/v1/models" or not self._guard_auth():
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({"object": "list",
                           "data": [{"id": STUB_MODEL, "object": "model"}]}
                          ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/v1/chat/completions" or not self._guard_auth():
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length") or 0)
        _StubColi.last_request = json.loads(self.rfile.read(length) or b"{}")
        _StubColi.last_auth = self.headers.get("Authorization")
        if _StubColi.behavior == "429":
            body = json.dumps({"error": {
                "message": "the admission queue is full",
                "type": "queue_full", "code": "queue_full"}}).encode()
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if _StubColi.last_request.get("stream"):
            self._serve_sse()
            return
        content = "" if _StubColi.behavior == "empty" else "A governed answer"
        body = json.dumps({
            "id": "chatcmpl-stub", "object": "chat.completion",
            "model": _StubColi.last_request.get("model", STUB_MODEL),
            "choices": [{"index": 0,
                         "message": {"role": "assistant",
                                     "content": content},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 9, "completion_tokens": 4,
                      "total_tokens": 13}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if _StubColi.behavior == "empty":
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            return
        pieces = ["Hel", "lo ", "gover", "ned world"]
        for piece in pieces:
            chunk = {"id": "chatcmpl-stub", "object": "chat.completion.chunk",
                     "choices": [{"index": 0,
                                  "delta": {"content": piece},
                                  "finish_reason": None}]}
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.flush()
            if _StubColi.behavior == "drop":
                # kill the socket mid-stream, exactly like a dying engine
                self.connection.close()
                return
        done = {"id": "chatcmpl-stub", "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {},
                             "finish_reason": "stop"}]}
        self.wfile.write(f"data: {json.dumps(done)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


@pytest.fixture(scope="module")
def coli_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubColi)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture()
def _reset_stub():
    _StubColi.behavior = "ok"
    _StubColi.api_key = ""
    _StubColi.last_request = {}
    _StubColi.last_auth = None
    yield
    _StubColi.behavior = "ok"
    _StubColi.api_key = ""


@pytest.fixture()
def colibri_cfg(coli_server, _reset_stub, monkeypatch):
    """Point the colibri module at the stub (config layer bypassed)."""
    monkeypatch.setattr(
        colibri_model, "app_config",
        lambda: {"model": {"colibri_url": coli_server,
                           "colibri_api_key": "",
                           "colibri_model": STUB_MODEL,
                           "request_timeout_s": 5,
                           "max_output_tokens": 128}})


@pytest.fixture()
def _provider_state():
    """Snapshot/restore provider module globals (no cross-test bleed)."""
    saved = (provider._backend, provider._requested,
             provider._last_fallback_reason)
    yield
    (provider._backend, provider._requested,
     provider._last_fallback_reason) = saved


# ---------- wire module: reachability ----------------------------------------
def test_healthy_true_against_stub(coli_server, colibri_cfg):
    assert colibri_model.healthy() is True


def test_healthy_false_when_closed_port(_reset_stub, monkeypatch):
    monkeypatch.setattr(
        colibri_model, "app_config",
        lambda: {"model": {"colibri_url": "http://127.0.0.1:59999",
                           "colibri_api_key": "",
                           "colibri_model": STUB_MODEL,
                           "request_timeout_s": 1,
                           "max_output_tokens": 128}})
    assert colibri_model.healthy() is False


# ---------- wire module: generate (JSON mode) --------------------------------
def test_generate_speaks_openai_contract(colibri_cfg):
    text = colibri_model.generate("SYSTEM", "USER QUESTION: hi",
                                  model=STUB_MODEL, think=False,
                                  max_tokens=77)
    assert text == "A governed answer"
    req = _StubColi.last_request
    assert req["model"] == STUB_MODEL
    assert req["max_tokens"] == 77
    assert req["temperature"] == 0.1
    assert req["stream"] is False
    assert [m["role"] for m in req["messages"]] == ["system", "user"]
    # reasoning_effort must NOT ride along when thinking was not requested
    assert "reasoning_effort" not in req


def test_generate_reasoning_effort_only_when_think(colibri_cfg):
    colibri_model.generate("SYSTEM", "USER QUESTION: hi", think=True,
                           max_tokens=10)
    assert _StubColi.last_request.get("reasoning_effort") == "low"


def test_generate_bearer_only_when_key_configured(coli_server, _reset_stub,
                                                  monkeypatch):
    monkeypatch.setattr(
        colibri_model, "app_config",
        lambda: {"model": {"colibri_url": coli_server,
                           "colibri_api_key": "local-secret",
                           "colibri_model": STUB_MODEL,
                           "request_timeout_s": 5,
                           "max_output_tokens": 128}})
    _StubColi.api_key = "local-secret"
    text = colibri_model.generate("SYSTEM", "USER QUESTION: hi",
                                  max_tokens=10)
    assert text == "A governed answer"
    assert _StubColi.last_auth == "Bearer local-secret"


def test_generate_429_maps_to_provider_unavailable(colibri_cfg):
    _StubColi.behavior = "429"
    with pytest.raises(colibri_model.ProviderUnavailable) as ei:
        colibri_model.generate("SYSTEM", "USER QUESTION: hi", max_tokens=10)
    assert "429" in str(ei.value)


def test_generate_connection_refused_is_provider_unavailable(_reset_stub,
                                                             monkeypatch):
    monkeypatch.setattr(
        colibri_model, "app_config",
        lambda: {"model": {"colibri_url": "http://127.0.0.1:59999",
                           "colibri_api_key": "",
                           "colibri_model": STUB_MODEL,
                           "request_timeout_s": 1,
                           "max_output_tokens": 128}})
    with pytest.raises(colibri_model.ProviderUnavailable):
        colibri_model.generate("SYSTEM", "USER QUESTION: hi", max_tokens=10)


# ---------- wire module: SSE streaming ---------------------------------------
def test_stream_yields_pieces_from_sse(colibri_cfg):
    pieces = list(colibri_model.generate_stream(
        "SYSTEM", "USER QUESTION: hi", model=STUB_MODEL, think=False,
        max_tokens=50))
    assert "".join(pieces) == "Hello governed world"
    assert _StubColi.last_request["stream"] is True


def test_stream_empty_raises(colibri_cfg):
    _StubColi.behavior = "empty"
    with pytest.raises(colibri_model.ProviderUnavailable):
        list(colibri_model.generate_stream("SYSTEM", "USER QUESTION: hi",
                                           max_tokens=10))


def test_stream_midstream_drop_raises(colibri_cfg):
    _StubColi.behavior = "drop"
    with pytest.raises(colibri_model.ProviderUnavailable):
        list(colibri_model.generate_stream("SYSTEM", "USER QUESTION: hi",
                                           max_tokens=10))


# ---------- backend registry: selection + fail-closed ------------------------
def test_resolve_backend_colibri_explicit_and_unknown_fail_closed(
        _provider_state):
    assert provider.resolve_backend("colibri") == "colibri"
    assert provider.backend_name() == "colibri"
    # unknown provider names must NEVER pretend to be the requested backend
    assert provider.resolve_backend("bogus-backend") == "mock"
    assert provider.backend_name() == "mock"
    assert provider._requested == "bogus-backend"


def test_auto_never_selects_colibri(_provider_state, monkeypatch):
    """auto stays ollama->mock: colibri is explicit opt-in only."""
    monkeypatch.setattr(ollama_model, "healthy", lambda timeout=0.4: False)
    assert provider.resolve_backend("auto") == "mock"


# ---------- provider chain: colibri through the shared loop ------------------
def test_provider_generate_colibri_success(coli_server, colibri_cfg,
                                           _provider_state, monkeypatch):
    monkeypatch.setattr(provider, "_backend", "colibri")
    monkeypatch.setattr(provider, "_routing", lambda backend=None: {
        "mode": "heuristic", "fast": STUB_MODEL, "reasoner": STUB_MODEL,
        "fast_tokens": 220, "reason_tokens": 600})
    gen = provider.generate("Explain the deployment process", "ctx",
                            "USER QUESTION: explain")
    assert gen.backend == "colibri"
    assert gen.model == STUB_MODEL
    assert gen.intent == "reason"
    assert gen.degraded is False
    assert gen.text == "A governed answer"
    assert _StubColi.last_request.get("reasoning_effort") == "low"


def test_provider_generate_colibri_degrades_visibly(coli_server, colibri_cfg,
                                                    _provider_state,
                                                    monkeypatch):
    """Engine saturated (429) -> retries -> VISIBLE mock fallback."""
    _StubColi.behavior = "429"
    monkeypatch.setattr(provider, "_backend", "colibri")
    monkeypatch.setattr(provider, "_routing", lambda backend=None: {
        "mode": "heuristic", "fast": STUB_MODEL, "reasoner": STUB_MODEL,
        "fast_tokens": 220, "reason_tokens": 600})
    monkeypatch.setattr(mock_model, "generate",
                        lambda q, c, general=False: "mock answer")
    gen = provider.generate("What is the wfh policy?", "ctx", "turn")
    assert gen.degraded is True
    assert gen.backend == "mock (fallback)"
    assert gen.model == "mock"
    assert "429" in gen.reason
    assert gen.text == "mock answer"


# ---------- routing defaults follow the backend ------------------------------
def test_routing_default_model_follows_colibri_backend(_provider_state,
                                                       monkeypatch):
    # _routing imports app_config at call time -> patch the source module
    monkeypatch.setattr(
        "src.common.paths.app_config",
        lambda: {"model": {"colibri_model": STUB_MODEL}})  # no fast_model
    r = provider._routing("colibri")
    assert r["fast"] == STUB_MODEL and r["reasoner"] == STUB_MODEL
    r = provider._routing("ollama")
    assert r["fast"] == "qwen2.5:0.5b"          # ollama default unchanged


def test_ollama_scoped_fast_reasoner_do_not_leak_into_colibri(
        _provider_state, monkeypatch):
    # Regression (big-model sweep): app_config.yaml ships fast_model /
    # reasoner_model = qwen2.5:0.5b for the ollama backend. With the
    # colibri backend active, those ollama-shaped defaults must fall back
    # to the colibri model id (a real coli serve has no ollama model-id:
    # every request would target a missing model and audit meta would
    # attribute the wrong model). Any other explicit value stays honored.
    monkeypatch.setattr(
        "src.common.paths.app_config",
        lambda: {"model": {"colibri_model": STUB_MODEL,
                           "ollama_model": "qwen2.5:0.5b",
                           "fast_model": "qwen2.5:0.5b",
                           "reasoner_model": "qwen2.5:0.5b"}})
    r = provider._routing("colibri")
    assert r["fast"] == STUB_MODEL and r["reasoner"] == STUB_MODEL
    r = provider._routing("ollama")
    assert r["fast"] == "qwen2.5:0.5b" and r["reasoner"] == "qwen2.5:0.5b"
    # deliberate distinct override still wins on the colibri backend
    monkeypatch.setattr(
        "src.common.paths.app_config",
        lambda: {"model": {"colibri_model": STUB_MODEL,
                           "fast_model": "glm-5.2-colibri-fast"}})
    r = provider._routing("colibri")
    assert r["fast"] == "glm-5.2-colibri-fast"


# ---------- status surface ----------------------------------------------------
def test_status_reports_colibri_only_when_in_play(coli_server, colibri_cfg,
                                                  _provider_state):
    provider.resolve_backend("mock")
    st = provider.status()
    assert st["colibri_reachable"] is None      # not requested -> no probe
    provider.resolve_backend("colibri")
    st = provider.status()
    assert st["colibri_reachable"] is True
    assert st["active_backend"] == "colibri"


# ---------- regression guard: ollama path untouched --------------------------
def test_ollama_chain_still_works(coli_server, colibri_cfg, _provider_state,
                                  monkeypatch):
    """The colibri addition must not disturb the ollama loop (same stub
    server proves the registry dispatch picks the right module)."""
    monkeypatch.setattr(provider, "_backend", "ollama")
    monkeypatch.setattr(provider, "_routing", lambda backend=None: {
        "mode": "heuristic", "fast": "fast-model-x", "reasoner": "big-model-y",
        "fast_tokens": 220, "reason_tokens": 600})
    monkeypatch.setattr(ollama_model, "generate",
                        lambda system, user_turn, model=None, think=None,
                        max_tokens=None: "Answer: ok")
    gen = provider.generate("What is the wfh policy?", "ctx", "turn")
    assert gen.backend == "ollama" and gen.model == "fast-model-x"
    assert gen.degraded is False
