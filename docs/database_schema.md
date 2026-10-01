# Database Schema — SecureLLM-Enterprise v3

All demo data is deterministic (seed 42 / 1337) and regenerable with one command:

```bash
python scripts/seed_company_data.py   # also writes data/company_data.sql
```

## Entity-relationship overview (text)

```
company.db (corporate trust domain)                executives.db (separate trust domain)
┌──────────────┐        ┌──────────────────┐       ┌────────────────────┐
│ users        │        │ employees        │       │ executives         │
│──────────────│        │──────────────────│       │────────────────────│
│ user_id PK   │        │ id PK            │       │ id PK              │
│ username  U  │        │ name             │       │ name               │
│ password_hash│ bcrypt │ department  ─────┼──┐    │ role (CEO/CFO/...) │
│ full_name    │        │ role             │  │    │ bonus (legacy)     │
│ email        │        │ email  (PII)     │  │    │ annual_salary      │
│ role         │──────┐ │ phone  (PII)     │  │    │ stock_options      │
│ department   │ RBAC │ │ salary (PII)     │  │    │ performance_bonus  │
│ clearance    │ L1-L5│ │ designation      │  │    │ contract_terms     │
│ is_active    │      │ │ bonus            │  │    └────────────────────┘
│ created_at   │      │ │ join_date        │  │
│ last_login   │      │ │ manager_id ──────┼──┼──► employees.id
└──────────────┘      │ │ address          │  │
                      │ └──────────────────┘  │
┌──────────────┐      │ ┌──────────────────┐  │      views (defence in depth)
│ documents    │      │ │ departments      │  │      employees_tech_view:
│──────────────│      │ │──────────────────│  │        id,name,department,role
│ doc_id PK    │      │ │ id PK            │  │        WHERE department='Tech'
│ title     U  │      │ │ name             │  │      employees_public_view:
│ content      │      │ │ manager          │  │        id,name,department,role,
│ department   │◄─┼───┘ └──────────────────┘  │        join_date   (NO PII)
│ sensitivity  │  │                           │
│ min_clearance│  └─ HR/Tech/Business/Finance/Executive
│ namespace    │
│ file_path    │     audit.db (append-only, hash-chained)
└──────────────┘     ┌────────────────────────────────────────────┐
                     │ audit (see below) · review_queue ·         │
                     │ pending_actions · audit_events (VIEW)      │
                     └────────────────────────────────────────────┘
```

## Table: `users` (authentication — Improvement 2)

| Column | Type | Notes |
|---|---|---|
| user_id | INTEGER PK AUTOINCREMENT | |
| username | TEXT UNIQUE NOT NULL | login id |
| password_hash | TEXT NOT NULL | **bcrypt, cost 12** — never plaintext |
| full_name / email | TEXT NOT NULL | profile |
| role | TEXT NOT NULL | Admin, Executive, HR_Manager, HR_Employee, Tech_Lead, Tech_Engineer, Business_Analyst, Finance_Manager, (legacy Tech_Employee) |
| department | TEXT NOT NULL | IT, Executive, HR, Tech, Business, Finance |
| clearance | TEXT NOT NULL | L1..L5 (drives CIA-C) |
| is_active | INTEGER DEFAULT 1 | 0 = cannot login |
| created_at / last_login | TIMESTAMP | |

Sample row (hash shortened):

```
user_id 4 | hr_manager | $2b$12$Xk... | Anjali Verma | anjali.verma@corp.example.com |
HR_Manager | HR | L4 | 1 | 2026-10-01 14:02:11 | 2026-10-01 14:20:37
```

## Table: `employees` (120 rows — enriched v2 schema, identity columns preserved)

| Column | Class | Notes |
|---|---|---|
| id | PK | |
| name | general | |
| department | general | HR / Tech / Business / Finance / Sales |
| role | general | job title used by RBAC queries |
| email / phone | **contact PII** | excluded from all views; L6 contact-DLP |
| salary | **compensation PII** | only HR_Manager / Finance_Manager / Executive / Admin roles |
| designation | general | = role (spec naming) |
| bonus | compensation | 0..~8% of salary |
| join_date | general | ISO date, 2015-2025 |
| manager_id | FK → employees.id | executives and senior staff |
| address | general | city-level only |

Sample rows:

```
12 | Rohan Iyer    | Tech     | SRE              | rohan.iyer@corp.example.com | ... | 132500 | SRE          | 9250  | 2019-06-11 | 3 | Pune, MH
48 | Kavya Reddy   | Finance  | FP&A Analyst     | kavya.reddy@corp.example.com| ... | 118000 | FP&A Analyst | 7350  | 2021-02-03 | 2 | Bengaluru, KA
```

**Views (Layer 3 defence in depth):** `employees_tech_view` (Tech rows, 4 safe columns) and `employees_public_view` (all rows, 5 safe columns — no salary/email/phone/address/bonus). The SQL query builder can only emit identifiers from `config/rbac_config.yaml`, and the connection is opened `mode=ro` at the SQLite level.

## Table: `executives` (6 rows — separate SQLite file = separate trust domain)

| Column | Notes |
|---|---|
| id, name, role | CEO / CFO / CTO / COO / CISO / CHRO |
| bonus | legacy column = performance_bonus (RBAC `executives.bonus`) |
| annual_salary / stock_options / performance_bonus | full compensation record |
| contract_terms | e.g. "3-year term, 12-month notice, clawback applies" |

Sample: `1 | Meera Nair | CEO | 2400000 | 24000000 | 520000 | 2400000 | 3-year term...`

## Table: `documents` (33 rows — RAG catalog)

| Column | Notes |
|---|---|
| title (UNIQUE) / content | content also written to `data/docs/<namespace>/<file>` and indexed |
| department | HR / Tech / Business / Finance / Executive |
| sensitivity | Public / Internal / Confidential / Restricted (CHECK constraint) |
| min_clearance | L1 / L2 / L3 / L5 — enforced by CIA-C |
| namespace | hr_docs / tech_docs / business_docs / finance_docs / exec_docs |
| file_path | provenance for auditors |

Distribution: 10 HR · 8 Tech · 6 Business · 4 Finance · 5 Executive.

## Table: `audit` (+ `audit_events` view — Layer 7)

| Column | Notes |
|---|---|
| id, ts | event id, ISO timestamp |
| user_id / username | acting account (also pre-login attempts, role `-`) |
| role | role at event time |
| action | LOGIN / QUERY / BLOCKED / APPROVED / DENIED / RATE_LIMITED |
| prompt (query_text) / ai_response (response_text) | redacted context stored separately |
| input_filter_action / output_filter_action | L2 / L6 decisions |
| blocked_by / layer_blocked | `L2`, `L3.5`, `L6`, `L2-rate`, `CIA-C`, `CIA-I`, `CIA-A` |
| cia_violation | **C / I / A or NULL** — the CIA category per event |
| reason | human-readable cause |
| prev_hash / hash | SHA-256 chain — tamper-evident (verify: `GET /admin/audit/verify`) |

`audit_events` is a convenience VIEW exposing the column names used in this doc (`event_id`, `timestamp`, `query_text`, ...). Sibling tables: `review_queue` (L6.5 withheld outputs) and `pending_actions` (L3.5 HITL lifecycle).

## Relationships & integrity rules

1. `users.role → config/rbac_config.yaml roles` — unknown role = the `default` policy (see nothing).
2. `users.clearance` rides in the JWT (`clr` claim) and is checked by CIA-C against `documents.min_clearance` tiers.
3. `employees.manager_id → employees.id` (self-reference; executives act as top-level managers).
4. `documents.namespace → data/docs/<namespace>/` — the seed keeps table and files in sync.
5. Executive data lives in a physically separate DB file; only the `executives` table (via policy) is ever reachable, and only for L5 roles.
6. The audit chain is append-only: no endpoint updates or deletes audit rows; verification walks every prev_hash/hash pair.
