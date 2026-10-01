"""Ingest the policy corpus into namespace-isolated vector indexes.

Namespaces mirror the RBAC role mapping in config/rbac_config.yaml:
    hr_docs / tech_docs / exec_docs
Run once after cloning (and whenever data/docs changes):
    python scripts/ingest_docs      # or: python -m scripts.ingest_docs
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.common.paths import DOCS_DIR, VECTOR_INDEX_DIR
from src.rag.vector_store import VectorStore, HAS_FAISS

NAMESPACES = ["hr_docs", "tech_docs", "exec_docs"]


def main():
    store = VectorStore()
    for ns in NAMESPACES:
        for path in sorted((DOCS_DIR / ns).glob("*.txt")):
            store.add(ns, path.stem, path.read_text(encoding="utf-8"),
                      {"title": path.stem})
            print(f"  + {ns}/{path.stem}")
    store.save(VECTOR_INDEX_DIR)
    backend = "FAISS IndexFlatIP" if HAS_FAISS else "NumPy cosine index"
    print(f"Saved vector indexes to {VECTOR_INDEX_DIR} (backend: {backend})")


if __name__ == "__main__":
    main()
