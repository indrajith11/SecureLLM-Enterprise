# NIST SP 800-53 Rev. 5 — Control Mapping

**Status: self-assessed mapping (moderate-baseline intent, single-system scope).** SP 800-53 is the control catalogue behind FedRAMP/FISMA; EY's JD names it alongside the AI frameworks. This document maps the families the JD highlights — **AC (Access Control), AU (Audit & Accountability), SI (System & Information Integrity), RA (Risk Assessment)** — control-by-control, then summarises partial coverage elsewhere. Notation: `✓` implemented with test evidence; `~` partial; `—` not applicable/out of scope for a single-node demo stack.

---

## AC — Access Control (family score: 12 controls addressed)

| Control | Name | Implementation | Evidence |
|---|---|---|---|
| AC-2 | Account management | 13 seeded accounts, role-versioned (`rv` claim), logout revocation | `test_rbac.py`, `test_login.py` |
| AC-2(3) | Disable inactive accounts | Brute-force lockout counters; session expiry 60 min | `test_auth_hardening.py` |
| AC-3 | Access enforcement | RBAC default-deny engine; clearance + department isolation on intent *and* retrieved docs | `test_rbac.py`, `test_denials.py` |
| AC-4 | Information flow enforcement | Namespace allow-list per role; no unscoped search API; context budgets | `test_tech_namespace_isolation` |
| AC-5 | Separation of duties | HITL: requester ≠ approver, atomic claim | `test_hitl.py` |
| AC-6 | Least privilege | Role → tables/columns/namespaces whitelists; `self_scope`, `row_scope`; aggregate whitelists | `config/rbac_config.yaml` |
| AC-6(1) | Need-to-know | Clearance model (L1–L5) gates Confidentiality checks | `docs/CIA_Mapping.md` |
| AC-6(9) | Log use of privileged functions | Admin actions audited: `MODEL_SELECT`, compliance writes, incident transitions all enter the hash chain | `test_compliance.py` |
| AC-7 | Unsuccessful logon attempts | Lockout with timing-equalized verification | `test_auth_hardening.py` |
| AC-8 | System use notification | Login page posture banner | UI screenshot 11_login_v4 |
| AC-12 | Session termination | JTI revocation on logout | `test_cookie_session.py` |
| AC-17 | Remote access | Bounded queues + payload caps shape any remote surface; TLS proxy documented in compose stack | `docs/Architecture.md` |

## AU — Audit & Accountability (family score: 9 controls) — strongest family

| Control | Name | Implementation | Evidence |
|---|---|---|---|
| AU-2 | Audit events | Prompt, context, response **and model identity** are audited; denial events first-class | `src/governance/audit.py` |
| AU-3 | Content of audit records | Full structured event + HMAC chain fields | database_schema.md |
| AU-4 | Audit storage capacity | Rotated JSONL SIEM mirror; retention purge configured | `test_audit_meta.py` |
| AU-5 | Response to audit failures | Chain verification endpoint reports `chain_valid`; SIEM mirror is the external correlation copy | `/admin/audit/verify` |
| AU-6 | Audit review & reporting | Admin console audit surface; compliance console reads live counts | `05_admin_console.png` |
| AU-7 | Audit reduction & report generation | Conformity-pack generator compiles audit-derived evidence automatically | `/admin/compliance/conformity-pack` |
| AU-8 | Time stamps | UTC ISO-8601 throughout | audit schema |
| AU-9 | Protection of audit information | HMAC-SHA256 hash chain — tampering detectable, re-keying detected via pinned key fingerprint in `audit_meta` | `test_audit_remediation.py` |
| AU-11 | Audit record retention | Retention purge **with chain re-anchoring** (records age out, chain stays verifiable) | documented in Architecture |

## SI — System & Information Integrity (family score: 8 controls)

| Control | Name | Implementation | Evidence |
|---|---|---|---|
| SI-1 | Policy & procedures | Firewall families documented; ruleset v2.0 version-stamped | probe reports |
| SI-2 | Flaw remediation | 42-finding register with fixes; pip-audit + gitleaks in CI | `docs/SECURITY_FIXES.md` |
| SI-3 | Malicious code protection | Output canary + injection-residue check (malicious-content containment at model boundary); NFKC/homoglyph normalisation kills evasion encodings | `test_input_filter_v2.py` |
| SI-4 | System monitoring | `/health`, Prometheus `/metrics`, per-request layer telemetry, rate-limit anomaly signals | `test_observability.py` |
| SI-7 | Software/firmware integrity | Corpus md5 stamped into every red-team report; MCP tool definitions pinned + hashed (design) | `scripts/probe_runner.py` |
| SI-8 | Spam/unsolicited protection | Oversized-prompt + payload-splitting rejection | corpus: `oversized_prompt`, `payload_splitting` |
| SI-10 | Information input validation | 22-family input firewall: direct override, authority, encoding, delimiter, unicode-evasion families + heuristic score gate | `test_input_filter_v2.py` |
| SI-11 | Error handling | Bounded 429/503 with `Retry-After`; no stack traces to clients; visible degradation banner instead of silent fallback | `test_availability.py` |

## RA — Risk Assessment (family score: 5 controls)

| Control | Name | Implementation | Evidence |
|---|---|---|---|
| RA-1 | Policy & procedures | Risk methodology: L×I, inherent → residual, residual ≤ inherent validated at API | `test_compliance.py` |
| RA-2 | Security categorisation | EU AI Act 4-tier classification at registration (deterministic; Art.5 prohibited → refused 403) | `test_compliance.py` |
| RA-3 | Risk assessment | Live scored register (7 seeded risks incl. self-risk) | `/admin/compliance/risks` |
| RA-5 | Vulnerability monitoring | pip-audit, gitleaks, dependency pinning in CI | CI badge row |
| RA-7 | Risk response | Control plans with named owners in register; incident SLAs | compliance console |

---

## Partial families (summary)

| Family | What exists | Grade |
|---|---|---|
| IA (Identification & Authentication) | bcrypt(12), pinned JWT alg, MFA gap documented (OIDC/SSO is the roadmap item) | ✓ strong core, ~ on IA-2(1)/2(2) MFA |
| SC (System & Comms Protection) | Read-only DB user, bound params, no write path, TLS proxy documented; local-only processing | ~ |
| AT (Awareness & Training) | Governance trace teaches per-user; no formal curriculum | ~ |
| CM (Configuration Management) | Declarative config, pinned deps, Docker compose; no SBOM yet (syft on roadmap) | ~ |
| IR (Incident Response) | Ledger + SLAs + runbook; no external IR retainer/analytics | ~ |

**Totals: 34 controls across the four named families addressed (AC 12, AU 9, SI 8, RA 5), plus 5 partial families.** Gaps are single-node demo gaps (MFA, SBOM, central SIEM) and are stated, not papered over.
