# Interview Pitch — how to talk about this project (simple English)

## The 60-second pitch (say it almost like this)

> "I built a project called SecureLLM-Enterprise. It's an enterprise AI
> chatbot where the recruiter line 'understanding of governance is
> appreciated' became working code.
>
> It starts with real multi-user identity: thirteen users — admin,
> executives, HR, engineers, finance — each with a bcrypt-hashed password
> and a signed 60-minute JWT carrying their role, department and clearance
> level, L1 to L5.
>
> The idea is simple: the LLM should never decide who sees what. So I built
> a layered pipeline. After authentication, every request is validated
> against the CIA triad for that specific user. Confidentiality: a
> deterministic classifier maps the question to a data domain and
> sensitivity, and the user's clearance and department are checked — an HR
> employee asking for Tech docs, or an engineer asking the CTO's salary,
> is refused before retrieval, before the model ever sees the prompt.
> Integrity: write operations are Admin-only, and even for the admin they
> become pending human approvals — never inline execution. Availability:
> twenty requests per minute and a maximum of three concurrent sessions
> per user — the fourth session is refused. Layer 2 is also an input
> firewall that decodes base64, hex and ROT13 and re-scans. Layer 3 is an
> RBAC policy engine written as YAML, so an auditor can read who can see
> what without reading code. Layer 4 retrieves data with role-scoped
> queries and namespace-isolated RAG. Layer 5 runs a local model — real
> qwen2.5 through Ollama — with a strict system prompt containing a canary
> token. Layer 6 checks the output: role-aware DLP, faithfulness, and an
> injection-residue check that catches RAG poisoning — when a poisoned
> document tells the model to say 'I HAVE BEEN HACKED', the output is
> blocked before the user sees it. Layer 7 writes every event into a
> hash-chained audit log tagged with the CIA pillar it touched.
>
> To prove it works, I wrote 72 attack probes across 12 categories. On the
> raw model, 30 out of 30 baseline attacks leaked data. With the layers
> on: zero out of 72 — 34 died at the input firewall, 21 at the new
> confidentiality check, 12 at output, 3 at access control, and 2 risky
> actions became pending human approvals. 137 automated tests cover it,
> including the full workflow: login, allowed query, cross-department
> block, write block, HITL approval, and audit verification. And it runs
> with real observability: /health and Prometheus /metrics, with per-pillar
> CIA block counters — all mapped to NIST AI RMF, the OWASP LLM Top 10,
> and the CIA triad."

## The short version (when they say "tell me in 4 lines")

> "I measured the baseline vulnerability of a raw small LLM with a
> 72-prompt red-team harness — it leaked 30 out of 30 times. With my
> governance layers plus per-user CIA enforcement active, it leaked 0 out
> of 72. Thirteen users log in with bcrypt credentials and clearance
> levels; every request is checked for confidentiality (clearance +
> department isolation), integrity (writes are Admin-only and HITL-gated)
> and availability (rate limit + session cap) — and every refusal lands in
> a hash-chained audit log with its CIA category. I also handled indirect
> prompt injection through poisoned RAG documents and ran it with real
> Prometheus observability, mapped to NIST AI RMF and the OWASP LLM Top 10."

## If they ask "why layers, why not one good filter?"

> "Because my report shows the layers catch different things. 34 attacks
> died at the input firewall, but 12 passed it and were caught at output —
> attacks like 'which employee earns the most' have no jailbreak words at
> all. And the new confidentiality check caught 21 more — clearance
> escalation attempts, cross-department asks, even a unicode-homoglyph
> jailbreak that slipped past the ASCII firewall but still had to name its
> target: 'bonuses'. Two risky actions became pending human approvals.
> Defence in depth is not a slogan here; I measured it."

## Likely questions and short natural answers

**Q: What is governance in one line, for you?**
> "Governance is making the rules about AI testable and provable — access
> rules a non-engineer can read, controls mapped to a framework like NIST
> AI RMF, and evidence: test reports and tamper-proof logs."

**Q: Map your project to NIST AI RMF.**
> "Govern is my policy-as-config — the RBAC YAML with nine roles and
> clearance levels, the action-gate patterns and the layered design. Map is
> my threat model — 12 entry-point threats documented. Measure is my
> 72-probe red-team harness, the RAG-poisoning demo, and continuous
> /metrics telemetry with per-pillar CIA counters. Manage is the HITL
> action gate with approver roles, the human review queue for withheld
> outputs, and the audit chain."

**Q: How do you stop prompt injection?**
> "Three independent nets. Input: patterns plus a heuristic score, and I
> decode base64, hex and ROT13 and re-scan, so encoding tricks fail.
> Capability: the model has no write access and no tools — even a
> successful injection cannot do damage. Output: role-aware DLP, a
> faithfulness check, and an injection-residue check — a policy answer is
> never allowed to contain instruction-like markers like 'SYSTEM OVERRIDE'.
> That last one catches indirect injection, when the attack arrives inside
> a retrieved document instead of the user's prompt."

**Q: What if the model hallucinates?**
> "Layer 6 checks every sensitive-shaped number in the answer against the
> retrieved context — digit-normalised, so '$2,400,000' must match
> '2400000' in the context. If the number was never in the context, the
> answer is blocked as unfaithful, not sent to the user."

**Q: What if the user asks the AI to DO something — delete a record?**
> "Two doors, both locked. If a normal user sends an explicit write —
> action_type DELETE — the integrity pillar refuses it: writes are
> Admin-only. If an Admin sends it, or the request just says 'delete
> employee Bob' in plain English, the agency gate — Layer 3.5 — turns it
> into a pending action request with an ID. The user hears 'Action
> Pending, waiting for approval'. Only an Executive or Admin role can
> confirm it through a separate endpoint, so the person who chats is never
> blindly the person who approves — segregation of duties. And even an
> approved action runs through a deliberately read-only sandboxed executor
> that verifies and logs but never mutates. That's OWASP LLM03 and the
> NIST Manage function as working code."

**Q: How do users actually log in — is it real authentication?**
> "Yes. Thirteen seeded accounts in a users table with bcrypt cost-12
> hashes — never plaintext. POST /api/login verifies and issues a signed
> JWT with user_id, username, role, department, clearance and a 60-minute
> expiry. Edge cases are tested: wrong password, unknown user, deactivated
> account, expired token, missing header, malformed token, tampered token,
> even an 'alg: none' forgery — all rejected with 401. The role and
> clearance claims are then the only identity inputs the rest of the
> pipeline trusts."

**Q: How exactly is the CIA triad enforced?**
> "Per user, per request, before retrieval. Confidentiality: a
> deterministic classifier maps the question to a department and a
> sensitivity tier — Public, Internal, Confidential, Restricted — and the
> user's clearance (L1 to L5) plus department are checked; Executive data
> requires L5 flat out. Integrity: write operations are Admin-only and get
> routed to human approval. Availability: twenty requests a minute and a
> maximum of three concurrent sessions per user. Every refusal carries its
> pillar in the response, a Prometheus counter, and a hash-chained audit
> row tagged 'C', 'I' or 'A'."

**Q: How do you know the system is healthy in production?**
> "Two operational endpoints. /health reports the model backend, whether
> Ollama is reachable, row counts of both data domains, whether the audit
> hash chain still verifies, and the HITL queue depth — it verifies
> tamper-evidence live. /metrics is Prometheus format: total requests by
> decision, blocked prompts per layer, output redactions, rate-limit
> rejections, pending actions, and latency histograms. A spike in blocked
> prompts is my incident signal. If Ollama dies mid-run, the app degrades
> to the deterministic mock and /health honestly says so — availability
> with honesty."

**Q: Did you run it on a real model?**
> "Yes — the provider layer auto-detects Ollama and runs qwen2.5:0.5b; one
> script, check_ollama, verifies the daemon, the model, and does a live
> governed generation before I demo. My measurement numbers use the
> deterministic mock so they're reproducible; the governance layers are
> model-agnostic and sit identically in front of the real model."

**Q: How is this connected to DPDP or Indian rules?**
> "DPDP's data minimisation and purpose limitation are implemented at
> Layer 4 — Tech staff get a database view without salary or contact
> columns at all. And the hash-chained audit trail is exactly the evidence
> trail you'd want if CERT-In reporting ever applies."

**Q: What is the weakest point of your project?** (they love honesty)
> "The input firewall is a deterministic heuristic, not an ML classifier —
> new paraphrases can pass it. I accept that because output DLP works on
> data shapes, not wording, and the residue check works on instruction
> markers — so the downstream nets are wording-independent. And my
> measured numbers use a mock model that simulates a vulnerable small LLM
> for reproducibility; the real-model path via Ollama is wired and tested."

## Bridge phrases (connect ANY answer back to governance)

- "...and that maps to the **Manage** function of NIST AI RMF."
- "...which is basically **data minimisation** from DPDP, implemented in code."
- "...so the control is **provable**, not just documented — I have the test."
- "...that's the **CIA triad**: confidentiality decided before the model,
  integrity checked after it, availability monitored around it."

## Do / don't

- DO say numbers: layered pipeline + CIA, 72 probes across 12 categories,
  0/72 vs 30/30, 137 tests passing, 34/21/12/3/2 split across layers, 13
  users with bcrypt + clearance levels.
- DO offer to show the repo, the login page + dashboard, the RAG-poisoning
  demo, and the trace screenshot — the UI shows every layer's decision as
  chips and the dashboard shows the user's own audit trail.
- DO offer the live ops view: `curl /health | jq` and `curl /metrics`.
- DON'T say "the model is safe". Say "the *system around* the model is
  measured, monitored, and the model is never trusted with access
  decisions or irreversible actions."
