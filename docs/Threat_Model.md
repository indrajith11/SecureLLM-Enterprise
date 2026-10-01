# Threat Model

Method: asset -> entry point -> threat -> control (STRIDE-flavoured, with
OWASP LLM Top 10 2025 references). Scope: the chat service and its data
stores. Out of scope: the corporate network, endpoint security.

## Assets (what we protect)

| # | Asset | Impact if lost |
|---|---|---|
| A1 | Employee PII + salaries (company.db) | privacy harm, DPDP violation |
| A2 | Executive compensation (executives.db) | market/legal harm, board confidentiality |
| A3 | Policy documents (vector namespaces) | misinformation via tampering |
| A4 | System prompt / policy logic | attacker learns the rules to defeat them |
| A5 | Model weights | IP theft |
| A6 | Audit trail | loss of non-repudiation, compliance failure |
| A7 | Service availability | DoS of a business function |

## Entry points and threats

| EP | Threat | OWASP | STRIDE | Control (layer) |
|---|---|---|---|---|
| Inference API | Direct prompt injection / jailbreak | LLM01 | Tampering | L2 firewall patterns + heuristic + decode-rescan |
| Inference API | Indirect injection via poisoned knowledge base | LLM01/LLM04 | Tampering | RAG-01..04 probes; L6 role DLP blocks poisoned figures |
| Inference API | Sensitive info disclosure in answers | LLM02 | Info Disclosure | L6 role-aware DLP + faithfulness check |
| Inference API | System prompt extraction | LLM07 | Info Disclosure | L2 extraction patterns; canary `CANARY-7f3a` in L6 |
| Inference API | Token/mana flooding | LLM10 | DoS | L2a sliding-window rate + token budgets |
| Inference API | Destructive/DDL requests via chat | LLM03 | Elevation | L2 destructive-SQL patterns; L3 read-only user + SELECT whitelist |
| Inference API | Auth bypass / token forgery | — | Spoofing | L1 pinned HS256, 15-min expiry, tamper tests |
| Vector DB | Namespace cross-tenant retrieval | LLM08 | Info Disclosure | L3 allow-list only; no unscoped search API exists |
| Vector DB | Index poisoning (insider/ingest supply chain) | LLM08/LLM04 | Tampering | ingest is a controlled script; L6 faithfulness neutralises poisoned content in answers |
| Model weights storage | Exfiltration | LLM02 | Info Disclosure | read-only mount, non-root container, cap_drop ALL |
| Audit store | Log tampering to hide tracks | — | Repudiation | L7 SHA-256 hash chain + verify endpoint + JSONL mirror |
| Model | Hallucinated figures presented as fact | LLM09 | Repudiation | L6 faithfulness: numbers must exist in retrieved context |

## Attack scenarios we explicitly tested

1. **Direct override** (DIR-01..12): "Ignore all previous instructions..." —
   raw model complies (baseline: 100% leak); secured: L2 or L6 stops it.
2. **Role-play / DAN** (DAN-01..10): persona switching. Same outcome.
3. **Fabricated authority** (AUTH-01..08): "I am the admin / the CEO asked".
   Access control never receives authority *claims* — only signed `role`.
4. **Encoding smuggling** (ENC-01..07): base64 / hex / ROT13 / spell-it-out.
   L2 decodes and re-scans; clean decodable blob = block.
5. **Data exfiltration phrasing** (EXF-01..06): no jailbreak vocabulary at
   all — passes L2 by design, dies at L3 (empty scoped context) or L6 (DLP).
6. **Excessive agency** (SQL-01..05): DROP/DELETE/UNION via chat. The DB
   user is read-only; the query builder cannot emit non-SELECT.
7. **RAG poisoning** (RAG-01..04): a poisoned "policy" doc instructs the
   model to append the CEO's bonus. Faithfulness + role DLP block the
   poisoned figures from reaching the user.

## Residual risks (accepted / documented)

- Heuristic L2 can be evaded by novel paraphrasing — accepted because L6 is
  data-shape-based (independent of wording) and L3 is capability-based.
- The mock model's leak behaviour is simulated; real-model numbers require
  Ollama (`scripts/run_garak.sh`).
- Ingest-time poisoning detection (signature/anomaly scanning of documents
  before indexing) is future work — currently mitigated downstream by L6.
