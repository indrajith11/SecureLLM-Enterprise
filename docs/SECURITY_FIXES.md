# Security & Quality Audit - Remediation Register

Every finding from the full-repository audit (42 findings: 5 Critical,
13 High, 16 Medium, 8 Low across six areas) and its resolution in this
codebase. Status legend: **FIXED** (code + regression test), **PARTIAL**
(primary exposure closed, remainder documented in `ROADMAP.md`),
**ACCEPTED** (inherent to a single-node reference implementation, with the
production swap point documented).

## Area A - Authentication & Sessions

| ID | Sev | Status | Resolution |
|---|---|---|---|
| AUTH-01 | Critical | FIXED (HTML) / PARTIAL (history) | Demo credentials removed from `login.html`; legacy `index.html` deleted. Credentials exist only in the seed script (which creates them) and `docs/demo_users.md` (operator doc). Git history is treated as exposed: this is a public demo dataset, never production data. Production path = OIDC/SSO provisioning (ROADMAP). |
| AUTH-02 | Critical | FIXED | The unsalted-SHA-256 YAML fallback store is DELETED. `config/users.yaml` is a no-secrets template; authentication is bcrypt-only against the `users` table. Plaintext-in-comments removed. |
| AUTH-03 | High | FIXED | No fallback store in the request path. Unknown user -> `None` (fail closed) with a dummy bcrypt verify so response timing does not leak username existence (AUTH-09). |
| AUTH-04 | High | FIXED | Login rate-limited + 5-failures/15-min lockout (5 min), audited as `L1-lockout` (v3.1; regression-tested). |
| AUTH-05 | High | FIXED | `POST /api/logout` revokes the token's jti; every request checks the revocation list (v3.1). |
| AUTH-06 | High | FIXED | `current_user` re-reads the account row on EVERY request (`auth.refresh_ctx`): role/department/clearance/active are live DB state; a deactivated or offboarded account loses access on its next call, not at token expiry. |
| AUTH-07 | Medium | FIXED | `verify_token()` rejects tokens missing `sub`/`role`/`dept`; missing/unknown clearance defaults to **L0** (the old default of L2 was a privilege hole). |
| AUTH-08 | Medium | FIXED | The `/token` legacy alias is deleted; probe tooling, tests and demo scripts use `/api/login`. |
| AUTH-09 | Low | PARTIAL | Cached read-only per-thread connections + dummy-verify timing equalisation are in. RS256/EdDSA + OIDC federation remain the documented production path (ROADMAP). |

## Area B - Chat Reply Pipeline

| ID | Sev | Status | Resolution |
|---|---|---|---|
| CHAT-01 | Critical | FIXED | `provider.generate()` retries Ollama with backoff, and if it still fails the fallback to mock is SURFACED: the reply body carries a visible degradation banner, `meta.degraded=true`, and /health reports the fallback reason. Never a silent brain swap. |
| CHAT-02 | High | FIXED | `POST /api/chat/stream` streams SSE end-to-end (Ollama native stream; the mock is word-chunked). Governance is the SAME `_preflight` code as the JSON path (no drift). Layer 6 runs incrementally per sentence + a full check at the end; a failing end-to-end check emits a `revoked` event that replaces the streamed message. |
| CHAT-03 | High | FIXED | Output filter v2: soft leaks (money/email/phone/faithfulness figures) are REDACTED with visible `[withheld - <shape>]` markers and delivered with reasons; card regex fires only on Luhn-valid numbers (order IDs pass); the blanket 'bonus' keyword hard-block is gone (figure governance is redaction + faithfulness). Config `output_filter.redact_instead_of_block` is now read (also closes the DEPLOY-05 dead key). |
| CHAT-04 | High | FIXED | Indian formats added to every DLP shape and to the probe leak detector: `+91 XXXXX XXXXX`, bare 10-digit IN mobiles, `12,00,000` lakh groups, `₹ 12 lakh / 1.2 crore` word forms. |
| CHAT-05 | Medium | FIXED | The system prompt now defines an explicit output contract (Answer / Sources / Confidence), a SOFT miss for gaps ("I don't have that in the data you are authorized to see..."), and two few-shot examples. "Access Denied" is reserved for real governance blocks so users can tell a policy denial from a data miss. |
| CHAT-06 | Medium | FIXED | Sensitivity is enforced from RETRIEVED DOCUMENT metadata (`documents` catalog -> vector meta -> `CIAEnforcer.check_retrieved_docs`), not only from question keywords. The keyword classifier stays as a fast-path pre-filter; the data check is authoritative for clearance tiers. Department isolation remains architectural (RBAC namespace allow-list). |
| CHAT-07 | Low | FIXED | Replies render with a mini-markdown renderer, cite Sources (namespace/id/score), and the governance trace stays behind a details toggle. |

## Area C - Database & RAG

| ID | Sev | Status | Resolution |
|---|---|---|---|
| RAG-01 | High | PARTIAL | The hashed embedder now includes word bigrams + char 3/4-grams with sublinear tf, and the lexical rerank is IDF-weighted (documented quality upgrade, zero new deps). The sentence-transformers swap point is documented in `ROADMAP.md`; it stays optional to preserve the zero-download install contract. |
| RAG-02 | High | FIXED | Entity-aware retrieval: named-person questions resolve via parameterised `WHERE name LIKE ?` probes (bounded); generic row dumps are capped (`retrieval.max_rows`, default 10); the whole context has a hard character budget (`retrieval.max_context_chars`, default 6000). |
| RAG-03 | High | FIXED | `save()` is atomic per namespace (temp file + `os.replace`); corrupt namespace files are skipped at load; a one-shot `ingest` container seeds the compose data volume so a fresh volume boots fully seeded. (pgvector/Qdrant migration remains the ROADMAP production path.) |
| RAG-04 | Medium | FIXED | The chain is HMAC-SHA256-signed (`AUDIT_HMAC_KEY` env, else derived from the JWT secret; key never stored in the DB; fingerprint pinned in `audit_meta`; key change on a populated chain fails closed). AND a deeper gap the audit missed is closed: the chain body now COVERS `ai_response` and `retrieved_context` - previously the answer text itself was tamperable without detection. |
| RAG-05 | Medium | FIXED | `verify_cached()` recomputes at most every 30 s and serves hot paths (/health, /api/stats); `GET /admin/audit/verify` forces a full walk. Appends no longer queue behind re-hashes. |
| RAG-06 | Medium | FIXED (core) | WAL journal + hot-path indexes (v3.1) + per-thread cached read-only connections for RBAC queries. A general connection pool / Redis-backed multi-worker state remains in ROADMAP. |
| RAG-07 | Medium | FIXED | Configurable retention (`audit.retention_days`, default 180) with a background purge job; purge re-anchors the chain genesis in `audit_meta` so history stays verifiable after deletion; the JSONL mirror rotates by size (10 MB, keeps .1/.2/.3). |
| RAG-08 | Low | FIXED | `add()` invalidates the built FAISS index as well as the matrix; feature hashing uses blake2b; an ingest-then-search regression test pins both. |

## Area D - Dashboard, Charts & Ops

| ID | Sev | Status | Resolution |
|---|---|---|---|
| DASH-01 | Critical | FIXED | The admin panel renders two Chart.js panels - requests-by-outcome doughnut and CIA-violation bars - fed from `/api/stats` (no backend change needed for the data). CSP was extended with the Chart.js CDN origin. |
| DASH-02 | High | PARTIAL | `esc()` escapes all five HTML-significant characters (quotes included); every interpolation (chips, class attrs, trace chips) is escaped; answers are escaped BEFORE markdown markers are upgraded. Token storage moves to HttpOnly cookies together with the OIDC work (ROADMAP) - noted honestly. |
| DASH-03 | Medium | FIXED | Security-headers middleware (v3.1): nosniff, DENY framing, no-referrer, conservative CSP. |
| DASH-04 | Medium | FIXED | `/health` is a minimal public probe (status/version/uptime/backend). Deep posture (row counts, chain state, Ollama URL, namespaces) moved to Admin-only `GET /admin/posture`. `/metrics` optionally requires a bearer scrape token (`METRICS_TOKEN`). |
| DASH-05 | Medium | FIXED | Audit endpoints clamp `limit` to <= 500; `/api/audit/all` returns the event total for paging. |
| DASH-06 | Medium | FIXED | The message cap lives in the Pydantic schema (`Field(max_length=4000)` -> 422 before any regex work); the config-driven in-pipeline guard (413) remains for lowered limits. Firewall regexes are precompiled (ReDoS surface reduced). |
| DASH-07 | Low | FIXED | Responsive grid with media queries (stacks below 900 px), audit table shows timestamps, Send disables during flight (v3.1), streaming keeps the UI live. |
| DASH-08 | Low | FIXED | `index.html` (the legacy demo that printed credentials in its dropdown) is deleted; one login/dashboard surface remains. |

## Area E - Config, Deploy & Supply Chain

| ID | Sev | Status | Resolution |
|---|---|---|---|
| DEPLOY-01 | Critical | FIXED | `JWT_SECRET` is REQUIRED by compose (`${JWT_SECRET:?...}` fails fast with instructions); the fallback secret file path is `SECRETS_DIR` (defaults to a writable volume in the container); no secret source at all -> the app raises a clear `SecretUnavailable` at boot instead of a 500 at first login. An `ingest` one-shot seeds the volume so the stack actually boots end-to-end. |
| DEPLOY-02 | High | FIXED | `.dockerignore` excludes `secrets.json`, `*.db`, `.env.*`, `deploy/.env`; CI verifies no database/secret files are tracked in git (db artifacts were also untracked). |
| DEPLOY-03 | High | FIXED | `SECURE_MODE=false` is REFUSED at boot unless BOTH `ENV=dev|baseline` AND `ALLOW_INSECURE_BASELINE=1` are set; the probe harness sets both explicitly for baseline measurement. |
| DEPLOY-04 | Medium | FIXED | All dependencies pinned to exact versions; Dockerfile pins `python:3.12.14-slim`, compose pins the Ollama image tag; CI runs pip-audit + gitleaks. Digest-pinning + SBOM noted in ROADMAP. |
| DEPLOY-05 | Medium | FIXED | Every config key is now read by code: `redact_instead_of_block` drives Layer 6; role `sensitive_patterns` from `rbac_config.yaml` merge into Layer 6 rules (additive, code baseline is the floor); `session.jwt_secret` is consulted by the secret resolver. |
| DEPLOY-06 | Low | FIXED | `app_config()` is mtime-cached (file edits still hot-reload; hot paths do zero disk IO). |

## Area F - Code Quality & CI

| ID | Sev | Status | Resolution |
|---|---|---|---|
| CODE-01 | Medium | FIXED | Approval is atomic: `claim()` transitions pending -> executing under the lock (double-confirm cannot double-execute); `finalise()` completes the transition; requester != approver is ENFORCED (403 + audit event); pending requests expire (`action_gate.expiry_minutes`, default 60). |
| CODE-02 | Medium | FIXED | Patterns compile once at import (`reload_patterns()` for explicit config reload); the sandbox target tokeniser filters stop-words ("remove the underperformer" -> `underperformer`). |
| CODE-03 | Low | FIXED | (v3.1) Pattern corpus compiles with `re.I`; probe corpus pins category behaviour. |
| CODE-04 | Low | FIXED | GitHub Actions CI runs pytest + the probe gate + gitleaks + pip-audit on every push; MIT LICENSE added; layer ids are strings (`["1","2","3.5",...]`); status contract documented and consistent: 401 auth / 403 policy deny / 413 payload / 422 validation / 429 rate+lockout / 503 load. |

## Measurement after remediation

- Tests: **206 passing** (was 137 at the audit baseline).
- Probe corpus: **84 probes / 22 categories**; secured mode **0/84 leaks**
  (69 governed blocks + 15 governed misses/redactions, 14 with visible
  `[withheld]` markers); baseline subset **30/30 leaks** (the raw model
  gives everything away with governance off).
- Secured-mode latency (governance included): **p50 2 ms / p95 5 ms**.
- Defence-in-depth split (secured): L2=44, CIA-C=20, L3+L4 access
  denial=15, L6 hard-block=3, L3.5 HITL=2.
