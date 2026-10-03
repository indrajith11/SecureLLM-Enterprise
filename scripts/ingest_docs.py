"""Ingest the policy corpus into namespace-isolated vector indexes.

Namespaces mirror the RBAC role mapping in config/rbac_config.yaml
(hr_docs / tech_docs / business_docs / finance_docs / exec_docs / it_docs /
legal_docs / ops_docs / trap_docs). Every namespace directory under
data/docs is ingested; reachability is decided by the RBAC allow-list
(trap_docs is granted to nobody by design).
Run once after cloning (and whenever data/docs changes):
    python scripts/ingest_docs      # or: python -m scripts.ingest_docs
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.common.paths import DOCS_DIR, VECTOR_INDEX_DIR
from src.rag.vector_store import VectorStore, HAS_FAISS

def main():
    store = VectorStore()
    n = 0
    for ns_dir in sorted(DOCS_DIR.iterdir()):
        if not ns_dir.is_dir():
            continue
        for path in sorted(ns_dir.glob("*.txt")):
            store.add(ns_dir.name, path.stem,
                      path.read_text(encoding="utf-8"),
                      {"title": path.stem})
            n += 1
            print(f"  + {ns_dir.name}/{path.stem}")
    store.save(VECTOR_INDEX_DIR)
    backend = "FAISS IndexFlatIP" if HAS_FAISS else "NumPy cosine index"
    print(f"Saved {n} documents to {VECTOR_INDEX_DIR} (backend: {backend})")


if __name__ == "__main__":
    main()
