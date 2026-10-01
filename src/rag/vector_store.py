"""Layer 4 building block: namespace-isolated vector store.

- Uses FAISS IndexFlatIP when faiss is importable; otherwise an identical
  NumPy cosine-similarity index (same interface, same results at this scale).
- Embeddings (Wave 4.1): TWO swappable embedders behind ONE interface -
    * hash (default): deterministic 256-dim hashing of words, word bigrams
      and character 3/4-grams with sublinear term weighting, L2-normalised.
      Zero external model downloads (the zero-download install contract).
    * st: sentence-transformers (config retrieval.st_model, default
      all-MiniLM-L6-v2) loaded LAZILY as a module singleton when
      retrieval.embedder=st. Opt-in keeps CI/hermetic runs dependency-free;
      vectors are never persisted (save() stores texts only), so switching
      embedders is a config change + restart - the matrix rebuilds from
      texts on first search. If the optional package is missing the mode
      falls back to hash; if the model fails at ENCODE time the request
      falls back per-call and the fallback is COUNTED (never silent).
- Isolation model: every search call MUST pass an explicit allow-list of
  namespaces. There is no API to search a namespace not on the list, which
  is what makes RAG poisoning + cross-tenant retrieval testable.

RAG-03 remediation: save() is now ATOMIC per namespace (write temp file ->
os.replace) so a crash can no longer leave a truncated JSON store behind.
RAG-08 remediation: add() invalidates the built FAISS index as well as the
cached matrix (ingest-then-search regression test pins this), and feature
hashing uses blake2b instead of MD5.
"""
import hashlib
import json
import os
import re
import tempfile
import threading
from pathlib import Path

import numpy as np

from src.common.paths import app_config, get_nested

try:
    import faiss  # type: ignore
    HAS_FAISS = True
except Exception:  # pragma: no cover - depends on environment
    HAS_FAISS = False

_DIM = 256
_WORD = re.compile(r"[a-z0-9]+")

_io_lock = threading.Lock()

# ---- Wave 4.1: embedder selection -----------------------------------------
# Module-level state; _EMBEDDER_TOKEN changes when the configured embedder
# changes, and VectorStore caches compare their token to rebuild matrices
# and clear query caches after an operator flips retrieval.embedder.
_EMB_LOCK = threading.Lock()
_EMBEDDER_OVERRIDE: str | None = None      # tests only
_EMBEDDER_TOKEN = ("hash", 0)              # (mode, failure-mode serial)
_ST_MODEL = {"obj": None}                  # lazy singleton


def _st_package_available() -> bool:
    try:
        import sentence_transformers  # noqa: F401
        return True
    except Exception:
        return False


def _embedder_mode() -> str:
    """Resolve the active embedder: 'st' only when configured AND the
    optional package is importable; otherwise 'hash'. _EMBEDDER_OVERRIDE
    (tests only) simulates the CONFIGURED mode - the availability check
    still applies to it."""
    if _EMBEDDER_OVERRIDE is not None:
        mode = _EMBEDDER_OVERRIDE
    else:
        cfg = app_config()
        mode = str(get_nested(cfg, "retrieval.embedder", "hash")).lower()
    if mode == "st" and not _st_package_available():
        return "hash"
    return mode if mode in ("hash", "st") else "hash"


def _embedder_state() -> tuple[str, int]:
    """(mode, fallback_serial) - the token stores compare against."""
    with _EMB_LOCK:
        return _EMBEDDER_TOKEN


def _bump_fallback() -> None:
    """A live 'st' encode failure switched this call to hash: bump the
    serial so every cached matrix/query is rebuilt under the new reality,
    and count the event (never a silent quality regression)."""
    global _EMBEDDER_TOKEN
    with _EMB_LOCK:
        mode, serial = _EMBEDDER_TOKEN
        _EMBEDDER_TOKEN = (mode, serial + 1)
    try:
        from src.governance import metrics
        metrics.AI_EMBEDDER_FALLBACKS.inc()
    except Exception:
        pass


def _st_model():
    """Lazy sentence-transformers singleton (first call downloads/loads)."""
    if _ST_MODEL["obj"] is None:
        from sentence_transformers import SentenceTransformer
        cfg = app_config()
        name = str(get_nested(cfg, "retrieval.st_model", "all-MiniLM-L6-v2"))
        _ST_MODEL["obj"] = SentenceTransformer(name)
    return _ST_MODEL["obj"]


def _hash_feature(feat: str) -> int:
    # blake2b (RAG-08): fast, modern, not flagged by crypto auditors
    digest = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big")


def _embed_hash(text: str) -> np.ndarray:
    """Hashed bag-of-features with sublinear (log) term weighting:
    words + bigrams + char 3/4-grams. The char n-grams make near-morphology
    matches work ('parental'~'parent', 'maternity'~'maternal'), which the
    old word-only buckets missed (RAG-01 partial remediation - the lexical
    IDF rerank in retriever.py completes it)."""
    vec = np.zeros(_DIM, dtype=np.float32)
    text = text.lower()
    words = _WORD.findall(text)
    feats: list[str] = list(words)
    feats += [f"{a} {b}" for a, b in zip(words, words[1:])]          # bigrams
    feats += [w[:i + 3] for w in words for i in range(min(3, len(w)))]  # pre3
    feats += [w[-(i + 3):] for w in words for i in range(min(3, len(w)))]  # suf3
    counts: dict[str, int] = {}
    for feat in feats:
        counts[feat] = counts.get(feat, 0) + 1
    for feat, tf in counts.items():
        h = _hash_feature(feat)
        idx, sign = h % _DIM, (1 if (h >> 63) & 1 == 0 else -1)
        vec[idx] += sign * (1.0 + np.log(tf))
    norm = np.linalg.norm(vec)
    return vec / norm if norm else vec


def _embed_st(text: str) -> np.ndarray:
    try:
        vec = _st_model().encode(text, normalize_embeddings=True)
        return np.asarray(vec, dtype=np.float32)
    except Exception:
        # Model load/encode failure mid-flight: degrade to hash for THIS
        # call, invalidate caches (dimension changes) and count it.
        _bump_fallback()
        return _embed_hash(text)


def embed(text: str) -> np.ndarray:
    """Single embedding entry point used by VectorStore - dispatches on
    retrieval.embedder (hash default). Same interface, swappable backend
    (the documented RAG-01 production swap point)."""
    global _EMBEDDER_TOKEN
    mode = _embedder_mode()
    with _EMB_LOCK:
        if _EMBEDDER_TOKEN[0] != mode:
            _EMBEDDER_TOKEN = (mode, _EMBEDDER_TOKEN[1])
    return _embed_st(text) if mode == "st" else _embed_hash(text)


class VectorStore:
    def __init__(self):
        self._texts: dict[str, list[dict]] = {}
        self._mat: dict[str, np.ndarray] = {}
        self._qcache: dict[str, np.ndarray] = {}   # S8: query-embedding LRU
        self._index: dict[str, object] = {}
        self._emb_token = _embedder_state()        # Wave 4.1 cache validity

    def _check_embedder(self) -> None:
        """Wave 4.1: if the active embedder changed (config flip or a live
        'st' failure), rebuild all derived caches - dimensions may differ."""
        token = _embedder_state()
        if token != self._emb_token:
            self._emb_token = token
            self._mat.clear()
            self._index.clear()
            self._qcache.clear()

    def add(self, namespace: str, doc_id: str, text: str, meta: dict | None = None):
        rows = self._texts.setdefault(namespace, [])
        rows.append({"id": doc_id, "text": text, "meta": meta or {}})
        self._mat.pop(namespace, None)
        self._index.pop(namespace, None)     # RAG-08: stale index must go

    def _matrix(self, namespace: str) -> np.ndarray:
        self._check_embedder()
        if namespace not in self._mat:
            self._mat[namespace] = np.stack(
                [embed(r["text"]) for r in self._texts[namespace]])
        return self._mat[namespace]

    def search(self, namespace: str, query: str, k: int = 3,
               min_score: float = 0.0) -> list[dict]:
        if namespace not in self._texts:
            return []
        self._check_embedder()
        # S8: cache the query embedding (same question -> same vector)
        q = self._qcache.get(query)
        if q is None:
            q = embed(query)
            if len(self._qcache) >= 256:
                self._qcache.clear()          # bounded, reset-on-full LRU
            self._qcache[query] = q
        mat = self._matrix(namespace)
        if HAS_FAISS:
            idx = self._index.get(namespace)
            if idx is None:
                idx = faiss.IndexFlatIP(mat.shape[1])
                idx.add(mat)
                self._index[namespace] = idx
            scores, ids = idx.search(q[None, :], min(k, len(self._texts[namespace])))
            pairs = zip(scores[0].tolist(), ids[0].tolist())
        else:
            sims = mat @ q
            order = np.argsort(-sims)[: min(k, len(sims))]
            pairs = [(float(sims[i]), int(i)) for i in order]
        return [{"score": round(s, 4), "id": self._texts[namespace][i]["id"],
                 "text": self._texts[namespace][i]["text"],
                 "meta": self._texts[namespace][i].get("meta", {}),
                 "namespace": namespace}
                for s, i in pairs if s >= min_score]

    def namespaces(self) -> list[str]:
        """Public inventory of loaded namespaces (used by /health)."""
        return sorted(self._texts.keys())

    # ---- persistence -------------------------------------------------
    def save(self, directory: Path):
        """RAG-03: atomic per-namespace persistence. Each file is written to
        a temp file in the same directory and os.replace()d into place - a
        crash mid-write can no longer corrupt the live index."""
        directory.mkdir(parents=True, exist_ok=True)
        with _io_lock:
            for ns, rows in self._texts.items():
                target = directory / f"{ns}.json"
                fd, tmp_path = tempfile.mkstemp(
                    dir=directory, prefix=f".{ns}.", suffix=".tmp")
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as fh:
                        json.dump(rows, fh, ensure_ascii=False)
                    os.replace(tmp_path, target)   # atomic on POSIX
                except Exception:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                    raise

    @classmethod
    def load(cls, directory: Path) -> "VectorStore":
        store = cls()
        if not directory.exists():
            return store
        for path in sorted(directory.glob("*.json")):
            try:
                store._texts[path.stem] = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                # corrupt namespace file: skip it rather than poison startup
                continue
        return store
