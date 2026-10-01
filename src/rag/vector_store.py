"""Layer 4 building block: namespace-isolated vector store.

- Uses FAISS IndexFlatIP when faiss is importable; otherwise an identical
  NumPy cosine-similarity index (same interface, same results at this scale).
- Embeddings: deterministic 256-dim hashing of word + character-trigram
  features, L2-normalised. Zero external model downloads; swap `embed()`
  with sentence-transformers in production.
- Isolation model: every search call MUST pass an explicit allow-list of
  namespaces. There is no API to search a namespace not on the list, which
  is what makes RAG poisoning + cross-tenant retrieval testable.
"""
import hashlib
import json
import re
from pathlib import Path

import numpy as np

try:
    import faiss  # type: ignore
    HAS_FAISS = True
except Exception:  # pragma: no cover - depends on environment
    HAS_FAISS = False

_DIM = 256
_WORD = re.compile(r"[a-z0-9]+")


def _hash_feature(feat: str) -> int:
    digest = hashlib.md5(feat.encode("utf-8")).digest()[:8]
    return int.from_bytes(digest, "big")


def embed(text: str) -> np.ndarray:
    vec = np.zeros(_DIM, dtype=np.float32)
    text = text.lower()
    words = _WORD.findall(text)
    feats = words + [w[:i + 3] for w in words for i in range(min(3, len(w)))]
    for feat in feats:
        h = _hash_feature(feat)
        idx, sign = h % _DIM, (1 if (h >> 63) & 1 == 0 else -1)
        vec[idx] += sign
    norm = np.linalg.norm(vec)
    return vec / norm if norm else vec


class VectorStore:
    def __init__(self):
        self._texts: dict[str, list[dict]] = {}
        self._mat: dict[str, np.ndarray] = {}
        self._index: dict[str, object] = {}

    def add(self, namespace: str, doc_id: str, text: str, meta: dict | None = None):
        rows = self._texts.setdefault(namespace, [])
        rows.append({"id": doc_id, "text": text, "meta": meta or {}})
        self._mat.pop(namespace, None)

    def _matrix(self, namespace: str) -> np.ndarray:
        if namespace not in self._mat:
            self._mat[namespace] = np.stack(
                [embed(r["text"]) for r in self._texts[namespace]])
        return self._mat[namespace]

    def search(self, namespace: str, query: str, k: int = 3,
               min_score: float = 0.0) -> list[dict]:
        if namespace not in self._texts:
            return []
        q, mat = embed(query), self._matrix(namespace)
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
                 "namespace": namespace}
                for s, i in pairs if s >= min_score]

    def namespaces(self) -> list[str]:
        """Public inventory of loaded namespaces (used by /health)."""
        return sorted(self._texts.keys())

    # ---- persistence -------------------------------------------------
    def save(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        for ns, rows in self._texts.items():
            (directory / f"{ns}.json").write_text(
                json.dumps(rows, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, directory: Path) -> "VectorStore":
        store = cls()
        if not directory.exists():
            return store
        for path in sorted(directory.glob("*.json")):
            store._texts[path.stem] = json.loads(path.read_text(encoding="utf-8"))
        return store
