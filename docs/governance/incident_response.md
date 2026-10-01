# Incident Response Runbook — SecureLLM-Enterprise

*Pre-deployment security gate, Step 10. Who does what, in the first hour, with the levers this codebase actually has. Every command here is real against this repo — no aspirational steps.*

---

## 0. Roles (small teams: one person may hold several)

| Role | Responsibility | Default |
|---|---|---|
| **Incident Commander (IC)** | declares/closes the incident, decides kill-switch use, owns the timeline | on-call engineer |
| **Ops responder** | executes the levers (env vars, compose, DB/archive) | platform/IT |
| **System owner** | stakeholder comms, DPO/legal contact for personal-data events | project owner |
| **Approver-of-record** | if HITL actions are implicated, freezes open pending actions | Admin |

Escalation order: on-call → system owner → DPO (personal-data exposure) → management. Write every action with timestamp + actor into the incident ticket from minute one — this runbook's evidence steps depend on it.

## 1. The levers (fastest first)

| Lever | Effect | Command / action |
|---|---|---|
| **Kill switch (AI off)** | every chat route returns 503; login/health/metrics/admin stay up; refusals counted in `ai_kill_switch_denials_total` | set `AI_ENABLED=false` in `deploy/.env`, then `docker compose -f deploy/docker-compose.yml up -d securellm` |
| **Model unplug** | no inference at all; app still boots and answers degrade with visible banners | `docker compose -f deploy/docker-compose.yml stop ollama` |
| **Full app stop** | nothing served; audit chain and volumes preserved | `docker compose -f deploy/docker-compose.yml stop securellm` |
| **Revoke all sessions (token-level)** | every issued JWT dies instantly | rotate `JWT_SECRET` (see §4) |
| **Disable one account** | user can no longer log in | `PATCH /admin/users/{username}` (`enabled: false`) as Admin — or `POST /api/logout` for one session |
| **Freeze high-risk actions** | no new HITL approvals | do NOT approve pending items; `GET /admin/review` to inspect queue |

**Rule of thumb:** suspected data leakage or model misbehaviour → kill switch first, investigate second. Availability can be restored; a leaked record cannot be un-leaked. The kill switch is deliberately cheap to use and cheap to reverse (one env var + one restart).

## 2. Scenario playbooks

### 2.1 Suspected sensitive-data disclosure (DLP bypass)
1. **Kill switch** (§1) — stop further outputs.
2. Snapshot evidence: `curl -H "Authorization: Bearer $ADMIN" https://<host>/admin/audit?limit=500 > evidence/audit.jsonl` and export `logs/audit.jsonl*` + `db/audit.db` from the volume (`docker compose cp securellm:/app/db/audit.db evidence/`).
3. Verify chain integrity: `GET /admin/audit/verify` — record `valid: true/false` **before** touching anything else.
4. Identify the violating rows (`action=BLOCKED` vs `action=QUERY` with L6 redactions), extract the prompt, role, and which rule family was bypassed.
5. Reproduce offline against the probe corpus: add the failing input to `tests/probes/jailbreaks.json`, run `python -m scripts.probe_runner --gate`. Fix = filter rule + test + green gate. Do not re-enable AI before 0/84 again.

### 2.2 Prompt-injection surge (many blocked prompts — `ai_blocked_prompts_total` spike)
1. Keep the app UP (L2b is doing its job; blocking is success).
2. Pull the recent audit rows, group by `blocked_by` and `reason`; identify the source campaign (same user? same document namespace?).
3. If a **document in the corpus** is the injection vector (indirect injection): remove/poison-quarantine that document, re-run ingest, and confirm the probe corpus's poison scenario still holds 0 leaks.
4. If a user is testing boundaries: standard HR process, not a technical one — the audit trail is the evidence.

### 2.3 Audit-chain verification failure (`/admin/audit/verify` → invalid)
1. **Treat as tampering until proven otherwise.** Freeze: stop writes (kill switch + app stop), take a **filesystem-level copy** of `db/audit.db` + `logs/audit.jsonl*` (volume snapshot, not a row export).
2. `GET /admin/audit/verify` returns the first failing `id` — inspect rows around it (`sqlite3 audit.db "SELECT id,ts,username,action,hash,prev_hash FROM audit WHERE id BETWEEN x-2 AND x+2"`).
3. Common false positive: `AUDIT_HMAC_KEY` changed on a populated chain (fails closed **by design**, §4). Confirm whether a key/env change happened at that timestamp before assuming malice.
4. Preserve original files read-only (`chmod 444`, checksum them, record checksums in the ticket). Never edit the live DB to "fix" the chain.

### 2.4 Model misbehaviour / bad answers post model change
1. Kill switch if answers are harmful; otherwise proceed live.
2. Check `provider.status()` via `/admin/posture` (`model` block) and the audit meta — which `backend`/`model` answered (per-answer attribution is in the chain).
3. Cross-check `docs/model_manifest.md`: did an `ollama pull` change a digest? → follow the manifest change procedure (re-run tests + probe gate) and roll the model back by re-tagging the previous version.
4. If Ollama is flapping (degraded banners everywhere): `stop ollama` → fix → `start`; the visible banner means users were told, but the incident ticket should still record the window.

### 2.5 Availability attack / consumption abuse
1. Watch `/metrics`: `ai_requests_total{decision="rate_limited"}`, `ai_chat_queue_depth`, `ai_kill_switch_denials_total`.
2. Identify the source user from audit `RATE_LIMITED` rows; disable the account if malicious (§1).
3. Tighten `rate_limit.*` / `availability.*` in `config/app_config.yaml` and restart; the bounded queue + per-user cap are already on — deeper limits are config, not code changes.
4. If the attack is volumetric at the network layer: that is a reverse-proxy/WAF problem — enable the TLS proxy profile (`--profile tls`) and apply connection limits at Caddy, or stop exposure at the firewall.

## 3. Evidence collection (the golden-hour checklist)

```bash
mkdir -p evidence && cd evidence
# 1. live posture + chain verdict (before anything changes)
curl -s -H "Authorization: Bearer $ADMIN" https://<host>/admin/posture | tee posture.json
curl -s -H "Authorization: Bearer $ADMIN" https://<host>/admin/audit/verify | tee verify.json
# 2. metrics snapshot
curl -s -H "Authorization: Bearer $METRICS_TOKEN" https://<host>/metrics | tee metrics.txt
# 3. the tamper-evident log itself (DB + SIEM mirror, all rotations)
docker compose -f deploy/docker-compose.yml cp securellm:/app/db/audit.db .
docker compose -f deploy/docker-compose.yml cp securellm:/app/logs/audit.jsonl .
# 4. checksum everything NOW; record in the ticket
sha256sum * | tee SHA256SUMS
```

The HMAC chain means any later dispute ("that answer was never given") can be settled from these files: `GET /admin/audit/verify` logic walks hash-over-body from genesis. Preserve, don't repair.

## 4. Key rotation procedures (code-accurate)

### `JWT_SECRET`
- Effect: every issued token becomes invalid → all users re-login (this **is** the kill-switch for sessions).
- Steps: set new `JWT_SECRET` in `deploy/.env` → `up -d securellm` → announce forced re-login.
- **Caution:** if `AUDIT_HMAC_KEY` is NOT explicitly set, the audit key is *derived from `JWT_SECRET`* — rotating it also rotates the audit key and fails the chain closed on a populated log (by design, §2.3). Therefore: **always set `AUDIT_HMAC_KEY` explicitly in production** and rotate the two keys independently.

### `AUDIT_HMAC_KEY` (audit-chain signing key)
- The chain **fails closed** if the key changes while rows exist — a populated chain signed by another key is exactly what key-tampering looks like. Rotation is therefore *archival + fresh chain*, not in-place re-signing:
  1. Set `AI_ENABLED=false` (kill switch) and stop the app.
  2. Archive `db/audit.db` + `logs/audit.jsonl*` per §3 (keep with the OLD key documented — the old files verify under the old key).
  3. Move the archived DB out of the volume (or start a fresh volume) so the app boots on an **empty** chain — an empty chain re-pins its fingerprint to the new key automatically (`_ensure_sign_key_pinned`).
  4. Set the new `AUDIT_HMAC_KEY`, remove the kill switch, restart. Record the rotation event + archive location in the ticket. Retention purges (`audit.retention_days`) re-anchor the genesis hash so day-to-day deletion never needs this procedure.

### Model credentials / API tokens
- `METRICS_TOKEN`: rotate in env, `up -d` — scrapers update theirs.
- No other third-party credentials exist by design (local models, local DBs) — that is the supply-chain posture working for you.

## 5. Post-incident (close the loop)

1. Timeline reconstructed from: audit chain (query rows are hash-pinned), Prometheus history, and the ticket.
2. Every technical gap found becomes a finding in `docs/SECURITY_FIXES.md` (the 42-finding register format) with a test that proves the fix — the same discipline as the hardening rounds.
3. Re-run the full gate before re-enabling: `pytest tests/` (278) + `python -m scripts.probe_runner --gate` (0/84) — then remove `AI_ENABLED=false`.
4. If personal data was exposed: notify per DPDPA process (DPO decides; the audit export is the breach record).
5. Blameless review: what lever was missing? Add it to this runbook in the same PR as the fix.
