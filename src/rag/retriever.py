"""Layer 4: Context retrieval (the "data fetcher").

The model NEVER sees a database connection or the whole vector store.
It only receives:
  - rows returned by the Layer 3 policy-built SELECT (least-privilege
    columns, department filter), and
  - documents retrieved ONLY from the role's allow-listed namespaces.

This is the practical form of two governance principles:
  - Data minimisation (DPDP Act 2023 s.6): fetch the fewest columns/rows
    that can answer the question.
  - Tenant/namespace isolation (OWASP LLM08: Vector & Embedding Weaknesses):
    there is no code path that searches a namespace outside the allow-list.
"""
from src.common.paths import VECTOR_INDEX_DIR, app_config, get_nested
from src.governance import rbac
from src.governance.rbac import Policy
from src.rag.vector_store import VectorStore

_cfg = app_config()
_TOP_K = int(get_nested(_cfg, "retrieval.top_k", 3))
_MIN = float(get_nested(_cfg, "retrieval.min_score", 0.12))

_WORD = __import__("re").compile(r"[a-z0-9]+")
_STOP = {"the", "a", "an", "is", "are", "of", "to", "for", "and", "or", "in",
         "on", "what", "which", "how", "our", "my", "me", "show", "give",
         "does", "do", "can", "i", "we", "you", "it", "this", "that", "with"}


def _lexical_rerank(hits: list[dict], question: str) -> None:
    """Hybrid retrieval: nudge each dense score up by the fraction of
    question content-words present in the document. The hashed embedding is
    coarse at this scale; a lexical overlap term keeps the obviously-relevant
    document on top (and keeps poisoned docs that target the question's own
    words where an attacker wants them - so Layer 6 still sees what the
    model sees)."""
    q_words = [w for w in _WORD.findall(question.lower()) if w not in _STOP]
    if not q_words:
        return
    for h in hits:
        blob = (h["id"] + " " + h["text"]).lower()
        overlap = sum(1 for w in q_words if w in blob) / len(q_words)
        h["score"] = round(h["score"] + 0.35 * overlap * overlap, 4)


def _render_rows(rows: list[dict]) -> str:
    if not rows:
        return ""
    lines = []
    for r in rows:
        lines.append("- " + ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in r.items()))
    return "DATABASE RECORDS (already filtered for your role):\n" + "\n".join(lines)


def _render_docs(hits: list[dict]) -> str:
    if not hits:
        return ""
    blocks = [f"POLICY DOCUMENT [{h['namespace']}/{h['id']}]:\n{h['text']}"
              for h in hits]
    return "KNOWLEDGE BASE CONTEXT (namespace-scoped):\n" + "\n\n".join(blocks)


def retrieve(policy: Policy, question: str, store: VectorStore) -> dict:
    """Returns {context, tables_queried, namespaces_searched, n_rows, n_docs}."""
    tables = rbac.intent_tables(question, policy)
    rows: list[dict] = []
    for table in tables:
        cols = policy.allowed_columns.get(table, [])
        dept = policy.departments[0] if (len(policy.departments) == 1
                                         and "department" in cols) else None
        rows.extend(rbac.run_select(policy, table, cols, dept))
    hits: list[dict] = []
    for ns in policy.allowed_namespaces:
        hits.extend(store.search(ns, question, k=_TOP_K, min_score=_MIN))
    _lexical_rerank(hits, question)
    hits.sort(key=lambda h: -h["score"])
    context = "\n\n".join(x for x in (_render_rows(rows), _render_docs(hits)) if x)
    return {"context": context, "tables_queried": tables,
            "namespaces_searched": policy.allowed_namespaces,
            "n_rows": len(rows), "n_docs": len(hits)}


def load_store() -> VectorStore:
    return VectorStore.load(VECTOR_INDEX_DIR)
