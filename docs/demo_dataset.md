# The demo dataset (v2): TechNova Solutions Pvt. Ltd.

The example enterprise behind every governance demo. One command builds the
whole thing, idempotently, and everything agrees with everything else
because the artifacts are generated FROM the governed database, not beside it:

```bash
python scripts/generate_enterprise_data.py      # full build (~1 min)
python scripts/generate_enterprise_data.py --skip-seed   # extend only
python scripts/setup_wizard.py                  # step 3/5 verifies it
```

Company: **TechNova Solutions Private Limited** — IT services, India,
HQ Bengaluru, founded 2015. Every number, name and identifier is FAKE
(deterministic seeds), shaped to look real so RBAC/DLP/PII demos are
believable.

## What gets built

| Layer | Contents | Where |
|---|---|---|
| SQL | 200 employees, 9 departments, companies, locations, teams, org_hierarchy, document_acl (747), data_classification, retention_rules, document_versions | `db/company.db` + `data/company_data.sql` |
| RAG corpus | 83 documents, 9 namespaces (5 legacy + it/legal/ops/trap) | `data/docs/` |
| PDFs | 83 styled twins, sensitivity banner + classification footer | `data/pdfs/<department>/` |
| Excel | 12 workbooks generated from the live DB | `data/excel/` |
| Images | logo, org chart, floor plan, 3 GST-style invoice scans | `data/images/` |
| Metadata | document / ACL / classification / retention / company YAMLs | `data/metadata/` |

## Departments & staff

Legacy: HR, Tech, Business, Finance, Sales (deterministic seed 42, untouched).
v2 additions (seed 2026): **IT (15), Legal (6), Marketing (10),
Operations (12)** plus backfill in HR/Tech/Finance — 67 new staff in a
dedicated id space (>= 200, tracked in `dataset_meta`), so legacy rows stay
byte-identical and re-running the generator is always safe.

## PII trust domain (the point of `employee_pii`)

`employee_pii` holds emp_code, PAN (`[A-Z]{5}[0-9]{4}[A-Z]`), Aadhaar
(fake 2xxx series), IFSC, bank account, personal email, date of birth for
ALL 200 staff — realistic shape, fake values.

**It is deliberately absent from `table_catalog` in
`config/rbac_config.yaml`.** The governed query builder only emits
identifiers from that catalog, so the chatbot is structurally blind to the
table — even Admin. Salary is protected by column policy; PAN/Aadhaar are
protected by *architecture* (defence in depth, DPDP Act 2023 s.6 data
minimisation — the same separate-trust-domain pattern as `executives.db`).
Field-level classification is recorded in the `data_classification` table
and `data/metadata/data_classification.yaml` so auditors see what is
protected where. Proven by `tests/test_enterprise_data.py::TestPIITrustDomain`.

## Document catalog (83)

- **33 legacy** (`src/db/doc_contents.py`): HR/Tech/Business/Finance/Exec.
- **50 v2** (`src/db/doc_contents_v2.py`): IT asset/MFA/vpn/licensing/AUP,
  legal NDA/MSA/DPDP/IP/vendor, finance budget/payments/close,
  ops facility/visitor/evacuation/BCP, business pricing/CRM/brand,
  tech coding/git/runbook/postmortem/architecture/on-call.
- **Versioned pair**: `leave_policy_2024` (superseded) vs
  `leave_policy_2026` (current) — lineage in `document_versions`; the
  retriever answers from the current revision.
- **Hindi**: `visitor_policy_hi`, `safety_guidelines_hi` — Devanagari
  bodies (correct shaping in PDFs via PIL+raqm; reportlab cannot shape
  complex scripts).
- **Trap decoys**: `trap_docs/vendor_renewal_notice` +
  `trap_docs/free_tool_advisory` carry REAL injection payloads and are
  granted to NO role (`trap_docs` in no `allowed_namespaces`) — the
  dataset ships its own indirect-injection evidence while staying inert.
  The live demo remains `python -m scripts.demo_rag_poisoning`.

## ACL matrix

`document_acl` (83 docs x 9 roles) is DERIVED from the live RBAC config at
generation time: `can_read` = namespace in the role's allow-list,
`can_download` = readable AND sensitivity in (Public, Internal). If the
policy changes, re-run the generator — the matrix cannot drift from what
the engine enforces. Exported to `data/metadata/document_acl.yaml`.

## Governance-aware retrieval (v2)

- `intent_tables` maps org/office/company questions to the new tables
  (locations/teams/companies/org_hierarchy — still only if the role may
  query them).
- The lexical reranker damps **script-mismatched** documents (an English
  question no longer ranks the Hindi twin above the English original) and
  boosts **identity matches** (the document whose slug IS the question's
  subject beats documents that merely mention it).

## Sensitivity x namespace coherence

Documents are tiered so no role is handed a namespace containing documents
above its clearance band (otherwise routine questions hard-fail at the
CIA-C data check, by design): Confidential lives only in namespaces
granted to L3+ roles; Restricted lives only in exec_docs (L5). The one
historical exception (`password_mfa`) is employee-facing policy and is
therefore `Internal`.
