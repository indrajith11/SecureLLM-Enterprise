#!/usr/bin/env python
"""Dataset v2 generator - the ONE-SHOT script behind the realistic
example-enterprise database (SQL + PDFs + Excel + images + metadata).

Idempotent end to end: reseeds the deterministic legacy dataset, extends
it with the v2 layer (new departments, 67 staff, PII trust domain, ACL /
classification / retention / version tables), renders 83 PDF twins,
12 Excel workbooks, 6 images and 5 metadata YAMLs, then rebuilds the
vector index with classification metadata and the portable SQL dump.

Usage:
    python scripts/generate_enterprise_data.py            # full build
    python scripts/generate_enterprise_data.py --skip-seed  # extend only
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    from src.db import doc_contents_v2, enterprise_ext
    doc_contents_v2.self_check()          # fail fast on catalog drift

    if "--skip-seed" not in sys.argv:
        from src.db import seed_company_data
        seed_company_data.main()          # legacy base: db + users + dump
        print()

    print("== extending database with dataset v2 ==")
    report = enterprise_ext.extend_everything()

    # the SQL dump must reflect the EXTENDED dataset (v2 tables included)
    from src.db.seed_company_data import PROJECT_DATA_SQL
    from src.db.seed_company_data import dump_sql, reingest_vectors
    dump_sql(PROJECT_DATA_SQL)
    print(f"== refreshed {PROJECT_DATA_SQL} ==")
    n = reingest_vectors()
    print(f"== vector index rebuilt: {n} chunks ==")
    print()
    enterprise_ext.print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
