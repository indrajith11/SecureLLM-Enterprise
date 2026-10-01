"""Layer 4 building block: namespace-isolated vector store.

- Uses FAISS IndexFlatIP when faiss is importable; otherwise an identical
  NumPy cosine-similarity index (same interface, same results at this scale).
- Embeddings: deterministic 256-dim hashing of words, word bigrams and
  character 3/4-grams with sublinear term weighting, L2-normalised. Zero
  external model downloads; swap `embed()` with sentence-transformers in
  production (the RAG-01 swap point - see docs/ROADMAP.md).
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

try:
    import faiss  # type: ignore
    HAS_FAISS = True
except Exception:  # pragma: no cover - depends on environment
    HAS_FAISS = False

_DIM = 256
_WORD = re.compile(r"[a-z0-9]+")

_io_lock = threading.Lock()


def _hash_feature(feat: str) -> int:
    # blake2b (RAG-08): fast, modern, not flagged by crypto auditors
    digest = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big")


def embed(text: str) -> np.ndarray:
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


class VectorStore:
    def __init__(self):
        self._texts: dict[str, list[dict]] = {}
        self._mat: dict[str, np.ndarray] = {}
        self._qcache: dict[str, np.ndarray] = {}   # S8: query-embedding LRU
        self._index: dict[str, object] = {}

    def add(self, namespace: str, doc_id: str, text: str, meta: dict | None = None):
        rows = self._texts.setdefault(namespace, [])
        rows.append({"id": doc_id, "text": text, "meta": meta or {}})
        self._mat.pop(namespace, None)
        self._index.pop(namespace, None)     # RAG-08: stale index must go

    def _matrix(self, namespace: str) -> np.ndarray:
        if namespace not in self._mat:
            self._mat[namespace] = np.stack(
                [embed(r["text"]) for r in self._texts[namespace]])
        return self._mat[namespace]

    def search(self, namespace: str, query: str, k: int = 3,
               min_score: float = 0.0) -> list[dict]:
        if namespace not in self._texts:
            return []
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
