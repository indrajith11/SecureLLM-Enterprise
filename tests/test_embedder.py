"""Wave 4.1 - the embedder swap point: real embeddings behind a feature flag.

Pinned guarantees:
  - default mode is hash: 256-dim, deterministic, zero downloads - the
    install contract is untouched;
  - retrieval.embedder=st engages sentence-transformers ONLY when the
    optional package is importable, otherwise graceful hash fallback;
  - a live 'st' encode failure falls back per-call, bumps the embedder
    token (all matrix/query caches rebuild - dimensions may differ) and
    increments ai_embedder_fallbacks_total (never silent);
  - VectorStore search results stay correct across an embedder switch
    mid-process (caches invalidated, no stale-dimension crashes).
"""
import numpy as np
import pytest

from src.rag import vector_store as vs


@pytest.fixture(autouse=True)
def _reset_embedder_state():
    """Isolate module-level embedder state between tests."""
    saved_token = vs._EMBEDDER_TOKEN
    yield
    vs._EMBEDDER_OVERRIDE = None
    vs._EMBEDDER_TOKEN = saved_token


def test_default_mode_is_hash_and_deterministic():
    assert vs._embedder_mode() == "hash"
    v1 = vs.embed("employee parental leave policy")
    v2 = vs.embed("employee parental leave policy")
    assert v1.shape == (256,)
    assert np.array_equal(v1, v2)
    norm = np.linalg.norm(v1)
    assert norm == pytest.approx(1.0, abs=1e-5)


def test_st_mode_without_package_falls_back(monkeypatch):
    """The zero-download contract: st requested but package absent -> hash."""
    monkeypatch.setattr(vs, "_st_package_available", lambda: False)
    monkeypatch.setattr(vs, "_EMBEDDER_OVERRIDE", "st")
    assert vs._embedder_mode() == "hash"
    v = vs.embed("anything")
    assert v.shape == (256,)


def test_st_mode_with_fake_model(monkeypatch):
    """With the package present, embed() dispatches to the ST singleton -
    simulated here with a deterministic fake encoder (384-dim like
    all-MiniLM-L6-v2)."""

    class FakeST:
        def encode(self, text, normalize_embeddings=True):
            v = np.zeros(384, dtype=np.float32)
            for i, ch in enumerate(text.lower().encode("utf-8")):
                v[(i * 7 + ch) % 384] += 1.0
            n = np.linalg.norm(v)
            return v / n if n else v

    monkeypatch.setattr(vs, "_st_package_available", lambda: True)
    monkeypatch.setattr(vs, "_EMBEDDER_OVERRIDE", "st")
    monkeypatch.setattr(vs, "_st_model", lambda: FakeST())
    assert vs._embedder_mode() == "st"
    v = vs.embed("hello world")
    assert v.shape == (384,)


def test_store_rebuilds_caches_after_embedder_switch(monkeypatch):
    """A store built under hash keeps working after a switch to 'st' mid-
    process: the token mismatch forces a matrix + query-cache rebuild."""
    class FakeST:
        def encode(self, text, normalize_embeddings=True):
            v = np.zeros(384, dtype=np.float32)
            v[hash(text) % 384] = 1.0
            return v

    store = vs.VectorStore()
    store.add("hr_docs", "leave", "Employees get 12 casual leave days.")
    store.add("hr_docs", "wfh", "Remote work is allowed 3 days per week.")
    hits = store.search("hr_docs", "how many leave days?", k=2)
    assert hits and hits[0]["id"] == "leave"       # hash embedder ranks it

    monkeypatch.setattr(vs, "_st_package_available", lambda: True)
    monkeypatch.setattr(vs, "_EMBEDDER_OVERRIDE", "st")
    monkeypatch.setattr(vs, "_st_model", lambda: FakeST())
    hits2 = store.search("hr_docs", "how many leave days?", k=2)
    assert hits2                                    # no crash on dim switch
    assert all(h["score"] >= 0 for h in hits2)


def test_live_encode_failure_falls_back_and_counts(monkeypatch):
    """A failing ST encode degrades to hash for that call, invalidates the
    caches (dimension change) and is COUNTED - never a silent regression."""
    from src.api.main import metrics

    class BrokenST:
        def encode(self, text, normalize_embeddings=True):
            raise RuntimeError("model files corrupt")

    monkeypatch.setattr(vs, "_st_package_available", lambda: True)
    monkeypatch.setattr(vs, "_EMBEDDER_OVERRIDE", "st")
    monkeypatch.setattr(vs, "_st_model", lambda: BrokenST())
    before = metrics.sample("ai_embedder_fallbacks_total") or 0.0
    v = vs.embed("some policy text")
    after = metrics.sample("ai_embedder_fallbacks_total") or 0.0
    assert v.shape == (256,)                        # hash fallback dimension
    assert after == before + 1


def test_st_missing_module_import_is_tolerated(monkeypatch):
    """_st_model import failure inside embed() must not break retrieval."""
    monkeypatch.setattr(vs, "_st_package_available", lambda: True)
    monkeypatch.setattr(vs, "_EMBEDDER_OVERRIDE", "st")

    def boom():
        raise ImportError("sentence-transformers not installed")

    monkeypatch.setattr(vs, "_st_model", boom)
    v = vs.embed("fallback please")
    assert v.shape == (256,)
