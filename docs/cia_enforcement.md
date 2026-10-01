# CIA Triad Enforcement — per user, per request (v3)

Module: `src/governance/cia_enforcer.py` · Pipeline wiring: `src/api/main.py::_chat_impl` · Tests: `tests/test_cia_enforcement.py`, `tests/test_full_workflow.py`

The CIA checks run **after Layer 1 (identity) and Layer 2 (input governance) and BEFORE retrieval (L4) and the model call (L5)**. A CIA refusal means the model never sees the prompt and no data is ever fetched for it. Everything is gated behind `secure_mode: true` — the honest baseline measurement (raw model, no governance) runs with CIA off, exactly like the other governance layers.

```
L1 auth ──► L2 rate limit ──► [CIA-A sessions] ──► L2 firewall ──► [CIA-C] ──► [CIA-I] ──► L3.5 ──► L3 ──► L4 ──► L5 ──► L6 ──► L7
                                   │                    │             │            │
                                   ▼ 429                ▼ 200         ▼ 200        ▼ 200
                             blocked_by CIA-A       blocked_by L2  blocked_by   blocked_by
                             cia_violation A                       CIA-C        CIA-I
                             (rate limit → CIA-A too)              cia_violation C   cia_violation I
```

Every response (allowed or blocked) carries `cia_checks: {confidentiality, integrity, availability}` = PASS/FAIL/SKIPPED and `layers_passed: [1, 2, 3.5, 3, 4, 5, 6, 7]`.

---

## C — Confidentiality ("who may know")

### Data classification

A deterministic keyword classifier (`classify_question`) maps every question to `(department, sensitivity)` — auditable, reproducible, no ML:

| Question contains | Classified as | Sensitivity |
|---|---|---|
| ceo / cto / cfo / board / bonus / stock options / M&A / succession / investor | **Executive** | **Restricted (L5)** |
| named department (HR/Tech/Business/Finance) **+** salary/earn/payroll | that department | **Confidential (L3)** |
| generic salary/earn/employee ask (no other department named) | user's own department | Internal (L2) |
| leave / benefits / grievance / recruitment / conduct | HR | Internal (L2) |
| budget / forecast / expense / procurement / treasury | Finance | Internal (L2) |
| deployment / runbook / incident / architecture / backup | Tech | Internal (L2) |
| strategy / competitor / pricing / playbook / market | Business | Internal (L2) |
| anything else | General (no isolation) | Internal (L2) |

### The three rules (checked in order)

```python
def check_confidentiality(user, requested_data_type, data_department, data_sensitivity):
    # Rule 1: clearance must meet the sensitivity tier
    if clearance_level(user.clearance) < clearance_level(required):
        return False, "Confidentiality violation: clearance L3 is insufficient for Restricted data (requires L5)"
    # Rule 2: department isolation (Executive + Admin exempt)
    if user.department != data_department and user.role not in ("Executive", "Admin"):
        return False, "Confidentiality violation: HR_Manager (HR) cannot access Tech data"
    # Rule 3: Executive data requires L5 regardless of role
    if data_department == "Executive" and user.clearance != "L5":
        return False, "Confidentiality violation: Executive data requires L5 clearance"
    return True, "Allowed"
```

Sensitivity → clearance mapping (same tiers as the `documents.min_clearance` column):

`Public → L1 < Internal → L2 < Confidential → L3 < Restricted → L5`

### Worked examples (all covered by tests)

| User (clearance, dept) | Asks | Outcome |
|---|---|---|
| hr_emp1 (L3, HR) | "Show me the Tech deployment runbook." | **BLOCKED (C)** — department isolation |
| tech_eng1 (L3, Tech) | "What is the CTO salary?" | **BLOCKED (C)** — Restricted needs L5 |
| tech_eng2 (L3, Tech) | "Upgrade me to L5 clearance…" | **BLOCKED (C)** — clearance escalation |
| hr_manager (L4, HR) | "What is the leave policy?" | ALLOWED — own dept, L4 ≥ L2 |
| ceo (L5, Executive) | anything | ALLOWED — L5 + role exemption |
| hr_hari (L4, HR) | "How much does everyone in Tech earn?" | **BLOCKED (C)** — cross-department compensation |

---

## I — Integrity ("who may change")

```python
def check_integrity(operation_type, user_role):
    # Rule 1: only Admin may even REQUEST a write operation
    if operation_type in ("DELETE", "UPDATE", "INSERT", "WRITE", "DROP") and user_role != "Admin":
        return False, "Integrity violation: HR_Manager cannot perform DELETE. ..."
    return True, "Allowed"
```

- The chat request body carries an explicit `action_type` (default `READ`). A non-Admin sending `DELETE`/`UPDATE`/`INSERT` is refused with `blocked_by: CIA-I`.
- **Rule 2 (AI faithfulness) is enforced by Layer 6**: every sensitive-shaped number in an output must exist in the retrieved context (hallucination / injected-leak guard).
- An **Admin** write intent is allowed through CIA-I only to be converted by the pipeline into a **Layer 3.5 pending action** (`source: chat_integrity_gate`) — an approver (Executive/Admin) must confirm, and even then execution happens in the deliberately read-only sandbox. The AI never executes anything, inline, ever.
- Defence in depth underneath: the RBAC query builder emits SELECT-only SQL, and the DB connection itself is opened `mode=ro` — even a bug cannot mutate data (OWASP LLM03).

| User | action_type | Outcome |
|---|---|---|
| hr_emp1 (HR_Employee) | DELETE | **BLOCKED (I)** |
| biz_analyst | UPDATE | **BLOCKED (I)** |
| admin | DELETE | HITL pending → admin confirms → APPROVED (sandboxed) |

---

## A — Availability ("who may consume")

Two per-user guards:

1. **Rate limit (Layer 2a)** — sliding window of 20 requests/min + 6k-token budget (`config/app_config.yaml → rate_limit`). Rejections return `429` with `blocked_by: L2-rate` and are audited with `cia_violation: A` — a DoS attempt *is* an availability violation, and the audit log says so.
2. **Concurrent session cap (CIA-A)** — max 3 live sessions per user (`availability.max_concurrent_sessions`); sessions are the JWT `jti`s seen in the last 60 minutes. The 4th distinct session gets `429 CIA-A`. Shared accounts cannot become covert multi-user seats, and a stolen credential cannot multiply itself.

Test evidence: 25 requests → exactly 20 pass, 5 refused; 4 logins → the 4th session refused while earlier sessions keep working.

---

## Observability & audit (every refusal is accountable)

| Signal | Where |
|---|---|
| `ai_cia_blocks_total{pillar="C"|"I"|"A"}` | Prometheus `/metrics` — per-pillar counters |
| `blocked_by: CIA-C / CIA-I / CIA-A` | API response field |
| `cia_checks: {confidentiality, integrity, availability}` | every API response |
| `cia_violation: C/I/A` + `layer_blocked` + `reason` | `audit` table row, hash-chained (L7) |
| per-user trail | `GET /api/audit/me` → own events + blocked attempts |
| admin view | `GET /api/audit/all` → full trail + `by_cia_violation` stats |

## Design honesty & production notes

1. The classifier is keyword-based on purpose: deterministic, testable, explainable to an auditor. A production upgrade path is a fine-tuned intent classifier with the same interface — but every production deployment should keep a deterministic allow/deny layer *in front* of it.
2. Department isolation exempts Executive and Admin by design (they legitimately span departments); rule 3 still caps non-L5 users out of Executive data.
3. Sessions are tracked in-process (single-node demo). Multi-node production would move the registry to Redis with the same TTL semantics.
4. CIA never replaces RBAC — it runs *before* RBAC and adds the clearance/department axis. RBAC still decides tables/columns/namespaces (L3), and L6 still checks the output (last line of defence).
