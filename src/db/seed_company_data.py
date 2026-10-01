"""Phase 2 seed: enhanced company data + users + vector index, in one shot.

1. generate_data.main()   -> company.db (120 enriched employees, departments,
                             33 documents, 2 minimised views) + executives.db
2. seed_users.seed()      -> users table (13 bcrypt accounts)
3. data/company_data.sql  -> portable SQL dump of the whole demo dataset
4. Vector re-ingest       -> all 5 namespaces (hr/tech/business/finance/exec)

Idempotent: safe to re-run at any time; ends with a printed row-count report.
"""
import shutil
import sqlite3
import sys
from pathlib import Path

from src.common.paths import (AUDIT_DB, COMPANY_DB, DATA_DIR,
                              DOCS_DIR, EXECUTIVES_DB, VECTOR_INDEX_DIR)
from src.db import generate_data, seed_users

PROJECT_DATA_SQL = DATA_DIR / "company_data.sql"


def dump_sql(path: Path) -> None:
    """Write a portable, human-auditable SQL dump of the demo dataset."""
    lines = ["-- SecureLLM-Enterprise demo dataset (deterministic, seed 42)",
             "-- Regenerate at any time: python scripts/seed_company_data.py",
             "BEGIN TRANSACTION;"]
    for db_file in (COMPANY_DB, EXECUTIVES_DB):
        label = db_file.stem
        lines.append(f"-- ============ {label}.db ============")
        src = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
        for (table_sql,) in src.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND "
                "name NOT LIKE 'sqlite_%' AND type IN ('table','view','index')"):
            lines.append(table_sql.rstrip(";") + ";")
        for (table,) in src.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND "
                "name NOT LIKE 'sqlite_%'").fetchall():
            cur = src.execute(f"SELECT * FROM {table}")  # noqa: S608 (catalog table)
            cols = [d[0] for d in cur.description]
            for row in cur.fetchall():
                vals = ", ".join(
                    "NULL" if v is None else
                    f"'{str(v).replace(chr(39), chr(39) * 2)}'"
                    for v in row)
                lines.append(f"INSERT INTO {table} ({', '.join(cols)}) "
                             f"VALUES ({vals});")
        src.close()
    lines.append("COMMIT;")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_store(namespaces: tuple[str, ...] | None = None):
    """Build a VectorStore from data/docs WITH classification metadata.

    CHAT-06: every document carries its sensitivity/department metadata from
    the doc_contents catalog, so the data-driven CIA-C verification
    (check_retrieved_docs) can authoritatively govern what was retrieved
    instead of trusting the question's keywords. Shared by seeding AND the
    probe harness (so the poison/restore cycle cannot wipe the metadata)."""
    from src.db.doc_contents import DOC_FILES
    from src.rag.vector_store import VectorStore
    ns_dept = {"hr_docs": "HR", "tech_docs": "Tech",
               "business_docs": "Business", "finance_docs": "Finance",
               "exec_docs": "Executive"}
    slug_meta: dict[str, dict] = {}
    for title, (ns, slug, dept, sens, _body) in DOC_FILES.items():
        slug_meta[slug] = {"sensitivity": sens,
                           "department": ns_dept.get(ns, dept),
                           "title": title}
    store = VectorStore()
    for ns_dir in sorted(DOCS_DIR.iterdir()):
        if not ns_dir.is_dir():
            continue
        if namespaces and ns_dir.name not in namespaces:
            continue
        for p in sorted(ns_dir.glob("*.txt")):
            store.add(ns_dir.name, p.stem, p.read_text(encoding="utf-8"),
                      slug_meta.get(p.stem, {"title": p.stem}))
    return store


def reingest_vectors() -> int:
    """Rebuild the vector index from data/docs across ALL namespaces."""
    tmp = VECTOR_INDEX_DIR.parent / "vector_index_rebuild"
    if tmp.exists():
        shutil.rmtree(tmp)
    store = build_store()
    n = sum(len(v) for v in store._texts.values())
    store.save(tmp)
    # atomic-ish swap so a running server keeps a consistent index
    if VECTOR_INDEX_DIR.exists():
        shutil.rmtree(VECTOR_INDEX_DIR)
    shutil.move(str(tmp), str(VECTOR_INDEX_DIR))
    return n


def main() -> None:
    print("== seeding company + executive databases ==")
    generate_data.main()
    print("== seeding users ==")
    n_users = seed_users.seed()
    print(f"users table: {n_users} accounts (bcrypt)")
    # Wave 2.4: demo identities need self-scope backing rows ("my salary" /
    # "my email" questions). Idempotent migration + insert. LIVE-BATTERY FIX:
    # a fresh clone seeded only via this script had no `username` column, so
    # every self-scope query died on sqlite3.OperationalError -> HTTP 500.
    from src.db.seed_self_rows import ensure_employee_self_rows
    print(f"employee self rows: {ensure_employee_self_rows()}")
    print("== writing data/company_data.sql ==")
    dump_sql(PROJECT_DATA_SQL)
    print(f"  -> {PROJECT_DATA_SQL}")
    print("== re-ingesting vector namespaces ==")
    n_docs = reingest_vectors()
    print(f"  {n_docs} documents indexed across "
          f"{len(sorted(p.name for p in DOCS_DIR.iterdir() if p.is_dir()))} "
          f"namespaces")
    print("== row-count report ==")
    ro = lambda db, q: sqlite3.connect(f"file:{db}?mode=ro", uri=True)  # noqa: E731
    for label, db, q in (
            ("employees", COMPANY_DB, "SELECT COUNT(*) FROM employees"),
            ("departments", COMPANY_DB, "SELECT COUNT(*) FROM departments"),
            ("documents", COMPANY_DB, "SELECT COUNT(*) FROM documents"),
            ("users", COMPANY_DB, "SELECT COUNT(*) FROM users"),
            ("executives", EXECUTIVES_DB, "SELECT COUNT(*) FROM executives")):
        conn = ro(db, q)
        print(f"  {label:12s} {conn.execute(q).fetchone()[0]}")
        conn.close()
    if AUDIT_DB.exists():
        print("  (audit.db left untouched - hash chain history preserved)")


if __name__ == "__main__":
    sys.exit(main())
