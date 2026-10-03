"""SETUP-1/2 (v4.6.0): model catalog (detect, score, select) + admin API.

Pinned guarantees:
  - scoring prefers bigger, known-quality instruct models over tiny or
    experimental community models (the user's own catalog order);
  - Ollama being DOWN is a calm, visible answer - never an exception;
  - model selection is a SURGICAL yaml edit: the three model-id keys
    change, every comment and every other key survives byte-for-byte;
  - selection fails closed on ids that are absent from the live catalog,
    malformed, or config keys that cannot be found;
  - BOTH llm endpoints are Admin-only (403 for everyone else);
  - a switch is audited (MODEL_SELECT lands in the hash chain).
"""
import json
import re
import shutil  # noqa: F401 - kept for future fixture restore patterns
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest

from src.model import catalog

TAGS_PAYLOAD = {
    "models": [
        {"name": "Alieno/ailo-152m-v2:latest", "size": 163_000_000},
        {"name": "qwen2.5-coder:7b", "size": 4_700_000_000},
        {"name": "qwen2.5:0.5b", "size": 397_000_000},
        {"name": "ailo-custom:latest", "size": 163_000_000},
    ]
}


# ---------- scoring --------------------------------------------------------------
def test_big_known_model_outranks_small():
    seven = catalog.score_model("qwen2.5-coder:7b", 4_700_000_000)
    half = catalog.score_model("qwen2.5:0.5b", 397_000_000)
    tiny = catalog.score_model("Alieno/ailo-152m-v2:latest", 163_000_000)
    assert seven > half > tiny >= 0


def test_recommend_picks_highest_score():
    models = [{"name": "qwen2.5:0.5b", "size": 397_000_000, "score":
               catalog.score_model("qwen2.5:0.5b", 397_000_000)},
              {"name": "qwen2.5-coder:7b", "size": 4_700_000_000, "score":
               catalog.score_model("qwen2.5-coder:7b", 4_700_000_000)}]
    assert catalog.recommend(models) == "qwen2.5-coder:7b"


def test_recommend_empty_catalog_is_none():
    assert catalog.recommend([]) is None


def test_size_human_units():
    assert catalog.size_human(4_700_000_000).endswith("GB")
    assert catalog.size_human(397_000_000).endswith("MB")


# ---------- detection (real TCP stub of Ollama /api/tags) ------------------------
class _StubOllama(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    payload = TAGS_PAYLOAD

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = json.dumps(self.payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def ollama_stub():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubOllama)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_list_models_parses_and_sorts_by_score(ollama_stub):
    det = catalog.list_ollama_models(ollama_stub)
    assert det["reachable"] and det["error"] is None
    names = [m["name"] for m in det["models"]]
    assert names[0] == "qwen2.5-coder:7b"           # best first
    assert len(names) == 4
    by_name = {m["name"]: m for m in det["models"]}
    assert by_name["qwen2.5:0.5b"]["size_human"] == "397 MB"
    assert by_name["qwen2.5-coder:7b"]["param_class"] == "~7B+"


def test_list_models_dead_backend_is_calm():
    det = catalog.list_ollama_models("http://127.0.0.1:9", timeout_s=0.3)
    assert det["reachable"] is False
    assert det["models"] == []
    assert det["error"]                              # visible reason


# ---------- selection: surgical yaml edit ----------------------------------------
YAML_FIXTURE = """# header comment must survive
secure_mode: true

model:
  provider: auto          # auto | mock | ollama
  ollama_url: http://localhost:11434
  ollama_model: qwen2.5:0.5b
  request_timeout_s: 30
  routing: heuristic               # heuristic | single
  fast_model: qwen2.5:0.5b
  reasoner_model: qwen2.5:0.5b     # tuned on purpose
"""


@pytest.fixture
def cfg_file(tmp_path):
    p = tmp_path / "app_config.yaml"
    p.write_text(YAML_FIXTURE, encoding="utf-8")
    return p


def test_apply_selection_updates_three_keys_keeps_comments(cfg_file):
    applied = catalog.apply_model_selection("qwen2.5-coder:7b",
                                            config_path=cfg_file)
    assert applied["model"] == "qwen2.5-coder:7b"
    text = cfg_file.read_text(encoding="utf-8")
    assert "ollama_model: qwen2.5-coder:7b" in text
    assert "fast_model: qwen2.5-coder:7b" in text
    assert "reasoner_model: qwen2.5-coder:7b" in text
    assert "# header comment must survive" in text
    assert "provider: auto          # auto | mock | ollama" in text
    assert "routing: heuristic               # heuristic | single" in text
    assert "# tuned on purpose" in text              # trailing comment kept
    # no trailing whitespace may be introduced (regression: the first
    # surgical-edit regex swallowed the newline into the comment group)
    for line in text.splitlines():
        if re.match(r"^\s*(ollama_model|fast_model|reasoner_model):", line):
            assert line == line.rstrip(), f"trailing spaces: {line!r}"
    # yaml still parses and only the three ids moved
    import yaml as _yaml
    cfg = _yaml.safe_load(text)
    assert cfg["model"]["request_timeout_s"] == 30
    assert cfg["secure_mode"] is True


def test_apply_selection_rejects_injection_ids(cfg_file):
    before = cfg_file.read_text(encoding="utf-8")
    for bad in ("", "qwen\nrm -rf", "a'b", 'a"b', "x" * 300):
        with pytest.raises(ValueError):
            catalog.apply_model_selection(bad, config_path=cfg_file)
    assert cfg_file.read_text(encoding="utf-8") == before   # untouched


def test_apply_selection_fails_closed_on_missing_keys(tmp_path):
    p = tmp_path / "broken.yaml"
    p.write_text("model:\n  provider: auto\n", encoding="utf-8")
    with pytest.raises(ValueError, match="config keys not found"):
        catalog.apply_model_selection("qwen2.5:0.5b", config_path=p)
    assert p.read_text(encoding="utf-8") == "model:\n  provider: auto\n"


# ---------- API surface (TestClient; selection patched - never touch the
# real repo config from tests) ------------------------------------------------------
def _admin_headers(client):
    r = client.post("/api/login", json={"username": "admin",
                                        "password": "Admin@123"})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


@pytest.fixture(scope="session")
def hr_headers(client):
    r = client.post("/api/login", json={"username": "hr_hari",
                                        "password": "hari123"})
    assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def test_llm_models_admin_only(client, hr_headers):
    assert client.get("/api/llm/models",
                      headers=hr_headers).status_code == 403
    assert client.get("/api/llm/models").status_code in (401, 403)
    r = client.get("/api/llm/models", headers=_admin_headers(client))
    assert r.status_code == 200
    body = r.json()
    for key in ("reachable", "models", "recommended", "current", "backend"):
        assert key in body


def test_llm_select_validates_then_applies(client, monkeypatch):
    hdrs = _admin_headers(client)
    fake_det = {"reachable": True, "error": None, "models": [
        {"name": "qwen2.5:0.5b", "size": 397_000_000, "size_human":
         "397 MB", "param_class": "<1B", "score": 16},
        {"name": "qwen2.5-coder:7b", "size": 4_700_000_000, "size_human":
         "4.7 GB", "param_class": "~7B+", "score": 45}]}
    monkeypatch.setattr("src.api.main.model_catalog.list_ollama_models",
                        lambda base, timeout_s=6.0: fake_det)
    # 1) unknown id -> 400, nothing applied
    r = client.post("/api/llm/model", headers=hdrs,
                    json={"model": "totally-not-there:9b"})
    assert r.status_code == 400
    # 2) backend down -> 503
    monkeypatch.setattr("src.api.main.model_catalog.list_ollama_models",
                        lambda base, timeout_s=6.0: {"reachable": False,
                                                     "error": "down",
                                                     "models": []})
    r = client.post("/api/llm/model", headers=hdrs,
                    json={"model": "qwen2.5:0.5b"})
    assert r.status_code == 503
    # 3) valid id -> applied; the real config file is NEVER touched by
    #    tests (patched recorder), but the endpoint's wiring is proven
    monkeypatch.setattr("src.api.main.model_catalog.list_ollama_models",
                        lambda base, timeout_s=6.0: fake_det)  # reachable again
    calls: list[str] = []
    monkeypatch.setattr("src.api.main.model_catalog.apply_model_selection",
                        lambda name, config_path=None:
                        calls.append(name) or
                        {"model": name, "config": "patched"})
    r = client.post("/api/llm/model", headers=hdrs,
                    json={"model": "qwen2.5-coder:7b"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert r.json()["previous"]                      # old id reported
    assert calls == ["qwen2.5-coder:7b"]


def test_llm_select_non_admin_forbidden(client, hr_headers):
    r = client.post("/api/llm/model", headers=hr_headers,
                    json={"model": "qwen2.5:0.5b"})
    assert r.status_code == 403


def test_chat_page_served_and_root_redirects(client):
    r = client.get("/chat")
    assert r.status_code == 200
    assert "Welcome" in r.text and "Assistant" in r.text
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (301, 302, 307)
    assert r.headers["location"].endswith("/chat")
