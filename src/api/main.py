"""SecureLLM-Enterprise API - the 7-layer governance pipeline + CIA triad.

Request flow (order IS the architecture):
  L1    Identity & Authentication   JWT verified, role/clearance extracted
  L2    Input Governance            rate limit -> session cap -> firewall
  CIA   Triad enforcement           C: clearance+dept isolation
                                    I: write ops Admin-only (then HITL)
                                    A: sessions + rate-limit feed
  L3.5  Agency Gate (HITL)          high-risk actions -> pending human approval
  L3    RBAC Policy Engine          role -> tables/columns/namespaces
  L4    Context Retrieval           policy-built SELECT + namespace RAG
  L5    Model                       strict system prompt + fenced context
  L6    Output Governance           role-aware DLP + canary + faithfulness +
                                    indirect-injection residue check
  L7    Audit                       hash-chained record for EVERY outcome

SECURE_MODE=false disables L2 firewall, CIA, L3.5 and L6 only - that is how
the baseline vulnerability report (garak_reports) is measured honestly:
same model, same data, no governance.

Per-user login (Improvement 2): POST /api/login verifies bcrypt credentials
from the users table and issues a 60-minute JWT. Endpoints: /api/me,
/api/audit/me (own trail), /api/audit/all (Admin), /api/stats (Admin),
/api/chat/stream (SSE), /login + /dashboard (UI pages).

Operations (CIA "Availability"): GET /health (minimal public probe) and
GET /metrics (Prometheus exposition; METRICS_TOKEN-gated when configured).
Deep posture moved behind Admin auth at GET /admin/posture (DASH-04).

Status-code contract (CODE-04): 401 auth, 403 policy deny (L2/L6/CIA),
413 payload, 422 validation, 429 rate/lockout, 503 load. Every deny body
carries blocked_by + cia_checks + layers_passed so clients can branch on
either the status code or the governance fields.
"""
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest, make_asgi_app
from pydantic import BaseModel, Field
import jwt as pyjwt

from src.common.paths import (AUDIT_DB, COMPANY_DB, EXECUTIVES_DB,
                              PROJECT_ROOT, app_config, get_nested)
from src.governance import actions, auth, cia_enforcer, denials, \
    input_filter, metrics, output_filter, rbac
from src.governance.audit import AuditChain
from src.governance.cia_enforcer import WRITE_OPS, classify_question
from src.governance.denials import ReasonCode
from src.governance.rate_limiter import SlidingWindowRateLimiter
from src.model import mock_model, ollama_model, provider
from src.model.prompts import SYSTEM_PROMPT, build_user_turn
from src.rag import retriever

cfg = app_config()
SECURE_MODE = bool(get_nested(cfg, "secure_mode", True))

# DEPLOY-03: the baseline switch must never reach production silently.
# SECURE_MODE=false disables L2/L6/CIA/L3.5 - the raw-model measurement
# mode - so it requires BOTH an explicit dev/baseline ENV and an explicit
# acknowledgement flag. One env var alone can no longer disarm the product.
_INSECURE_ACK = os.environ.get("ALLOW_INSECURE_BASELINE", "") == "1"
_ENV = os.environ.get("ENV", "dev")
if not SECURE_MODE and not (_INSECURE_ACK and _ENV in ("dev", "baseline")):
    raise RuntimeError(
        "SECURE_MODE=false refused: this disables the input firewall, DLP, "
        "CIA and HITL gates and the mock model will serve REAL seeded data. "
        "Allowed only for controlled baseline measurement with ENV=dev|baseline "
        "AND ALLOW_INSECURE_BASELINE=1.")

# DASH-04: /metrics optionally requires a bearer scrape token. Set
# METRICS_TOKEN in the environment (compose/K8s secret) to lock it down.
METRICS_TOKEN = os.environ.get("METRICS_TOKEN", "")

APPROVER_ROLES = set(get_nested(cfg, "action_gate.approver_roles", ["Executive"]))
ADMIN_ROLES = {"Admin"}
_START_TIME = time.time()

app = FastAPI(
    title="SecureLLM-Enterprise",
    description="Governance-enforced enterprise AI chatbot "
                "(NIST AI RMF + OWASP LLM Top 10 + CIA triad)",
    version="4.0.0")
audit = AuditChain()
audit.start_maintenance()          # RAG-07: retention purge + rotation loop
limiter = SlidingWindowRateLimiter(
    requests_per_minute=int(get_nested(cfg, "rate_limit.requests_per_minute", 20)),
    token_budget_per_minute=int(get_nested(cfg, "rate_limit.token_budget_per_minute", 6000)))
cia = cia_enforcer.CIAEnforcer(
    max_sessions=int(get_nested(cfg, "availability.max_concurrent_sessions", 3)),
    session_ttl_minutes=int(get_nested(cfg, "availability.session_ttl_minutes", 60)))
est_cpt = int(get_nested(cfg, "rate_limit.est_chars_per_token", 4))
block_score = float(get_nested(cfg, "input_filter.block_score", 6.0))
store = retriever.load_store()
provider.resolve_backend(get_nested(cfg, "model.provider", "auto"))
actions_store = actions.PendingActionStore()


# ---- S2 hardening: security headers on every response -----------------------
@app.middleware("http")
async def _security_headers(request: Request, call_next):
    """Browser-facing hardening: clickjacking, MIME sniffing, referrer and
    a conservative CSP (inline kept for the bundled static UI)."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' "
        "https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' "
        "https://cdn.jsdelivr.net; img-src 'self' data:; "
        "connect-src 'self'")
    return response


@app.middleware("http")
async def _http_metrics(request: Request, call_next):
    """Every HTTP hit becomes an http_requests_total sample with a
    bounded-cardinality path label (/api/action/confirm/17 -> {id}).
    Continuous monitoring = ISO 27001 A.8.16 / SOC 2 CC7.2 / NIST Measure."""
    status_code = "500"
    try:
        response = await call_next(request)
        status_code = str(response.status_code)
        return response
    finally:
        metrics.HTTP_REQUESTS.labels(
            request.method,
            metrics.normalise_path(request.url.path),
            status_code).inc()
        metrics.observe_uptime()


class ChatRequest(BaseModel):
    # DASH-06: the length cap lives in the schema itself, so oversized
    # bodies are rejected with 422 before ANY expensive regex work runs.
    message: str = Field(..., max_length=4000)
    action_type: str = "READ"     # READ (default) | DELETE | UPDATE | INSERT

    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


class TokenRequest(BaseModel):
    username: str
    password: str


class ActionRequestBody(BaseModel):
    action_type: str
    target: str
    justification: str = ""

    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


def current_user(request: Request) -> auth.UserCtx:
    """Layer 1 dependency: signature + expiry + logout revocation + LIVE
    account re-validation (AUTH-06). Role/department/clearance/active are
    refreshed from the database on every request - a downgraded, offboarded
    or deactivated account loses access on its very next call, not at token
    expiry. Fails closed when the account has vanished."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    try:
        user = auth.verify_token(header.removeprefix("Bearer ").strip())
    except pyjwt.PyJWTError as exc:
        raise HTTPException(401, f"invalid token: {exc.__class__.__name__}")
    if auth.is_revoked(user.session_id):
        raise HTTPException(401, "token revoked (logout)")
    user = auth.refresh_ctx(user)
    if not user.active or not user.role:
        # account deleted / deactivated / unknown since the token was issued
        audit.append(user_id=user.username, role="-", prompt="(request)",
                     retrieved_context="", ai_response="[stale token]",
                     input_action="n/a", output_action="n/a",
                     blocked_by="L1-stale", latency_ms=0.0,
                     action="DENIED",
                     reason="account state changed since token issue")
        raise HTTPException(401, "account state changed - sign in again")
    return user


def _deny(user, prompt, layer, reasons, latency, trace=None,
          cia_checks=None, layers=None, cia_violation=None,
          status_code: int = 403,
          denied_code: "ReasonCode | None" = None):
    """Policy deny. CODE-04: consistent 403 for governance refusals
    (L2 firewall, L6 DLP, CIA-C/I) so clients can branch on status alone;
    the body still carries blocked_by + full trace for explainability.
    Denial Engine (Wave 1.1): when denied_code is set, the reply is the
    official 4-part refusal (head keeps the legacy reserved-phrase contract;
    the engine appends policy citation + 'You can view' + escalation path)
    and the reason code rides in the body, meta and audit record."""
    reason_txt = reasons
    if denied_code is not None:
        reason_txt = f"denied_code={denied_code.value}; {reasons}"
    audit.append(user_id=user.username, role=user.role, prompt=prompt,
                 retrieved_context="", ai_response=f"[{layer} blocked]",
                 input_action="blocked" if layer == "L2" else "n/a",
                 output_action="blocked" if layer == "L6" else "n/a",
                 blocked_by=layer, latency_ms=round(latency, 1),
                 action="BLOCKED", cia_violation=cia_violation,
                 layer_blocked=layer, reason=reason_txt)
    metrics.AI_BLOCKED.labels(layer).inc()
    metrics.AI_REQUESTS.labels("blocked").inc()
    if denied_code is not None:
        metrics.AI_DENIALS.labels(denied_code.value).inc()
    body = {"response": (
        f"Request blocked by {layer} security governance: {reasons}. "
        "This event has been logged.")
        if denied_code is None else denials.render(
            denied_code, user.role, allowed=rbac.get_policy(user.role).summary(),
            head=(f"Request blocked by {layer} security governance: "
                  f"{reasons}. This event has been logged.")),
        "blocked_by": layer,
        "cia_checks": cia_checks or {},
        "layers_passed": layers or [],
        # full layer trace on blocked responses too: the governance
        # decision must be explainable to the user and to auditors
        "meta": {"trace": trace or [], "latency_ms": round(latency, 1),
                 "secure_mode": SECURE_MODE,
                 "backend": provider.backend_name()}}
    if denied_code is not None:
        body["denied_code"] = denied_code.value
        body["meta"]["denied_code"] = denied_code.value
    if status_code != 200:
        return JSONResponse(status_code=status_code, content=body)
    return body


def _cia_deny(user, prompt, pillar, layer, reason, latency, trace,
              cia_checks, layers, status_code=403,
              denied_code: "ReasonCode | None" = None):
    """CIA triad refusal: explainable, hash-chained, counted per pillar.
    CODE-04: confidentiality/integrity refusals are 403; availability
    refusals pass status_code=429 at the call site.
    Denial Engine (Wave 1.1): confidentiality refusals carry CIA_C_DOC and
    the official 'You can view' + escalation parts (legacy head kept)."""
    metrics.AI_CIA_BLOCKS.labels(pillar).inc()
    metrics.AI_BLOCKED.labels(layer).inc()
    metrics.AI_REQUESTS.labels("blocked").inc()
    if denied_code is not None:
        metrics.AI_DENIALS.labels(denied_code.value).inc()
    reason_txt = reason if denied_code is None else \
        f"denied_code={denied_code.value}; {reason}"
    audit.append(user_id=user.username, role=user.role, prompt=prompt,
                 retrieved_context="", ai_response=f"[{layer} blocked]",
                 input_action="n/a", output_action="n/a",
                 blocked_by=layer, latency_ms=round(latency, 1),
                 action="BLOCKED", cia_violation=pillar,
                 layer_blocked=layer, reason=reason_txt)
    body = {"response": (
        f"Access Denied. {reason}. This event has been "
        "logged to the tamper-evident audit chain.")
        if denied_code is None else denials.render(
            denied_code, user.role, allowed=rbac.get_policy(user.role).summary(),
            head=(f"Access Denied. {reason}. This event has been logged to "
                  "the tamper-evident audit chain.")),
        "blocked_by": layer,
        "cia_checks": cia_checks,
        "layers_passed": layers,
        "meta": {"trace": trace, "latency_ms": round(latency, 1),
                 "secure_mode": SECURE_MODE,
                 "backend": provider.backend_name()}}
    if denied_code is not None:
        body["denied_code"] = denied_code.value
        body["meta"]["denied_code"] = denied_code.value
    if status_code != 200:
        return JSONResponse(status_code=status_code, content=body)
    return body


def _authz_deny(req, user, code: ReasonCode, detail: str, t0: float,
                trace: list, cia_checks: dict, layers: list) -> dict:
    """Denial Engine (Wave 1.1): an authorisation refusal is a NORMAL
    business outcome, not a security incident - so it is a 200 chat reply
    with the official 4-part refusal, a stable denied_code for clients, and
    a hash-chained audit record (reason carries denied_code=<CODE>)."""
    code = ReasonCode(code)
    trace.append({"layer": "L3", "check": "field_intent_authorised",
                  "result": "blocked", "denied_code": code.value})
    metrics.AI_DENIALS.labels(code.value).inc()
    metrics.AI_BLOCKED.labels("L3").inc()
    metrics.AI_REQUESTS.labels("blocked").inc()
    audit.append(user_id=user.username, role=user.role, prompt=req.message,
                 retrieved_context="", ai_response=f"[denied: {code.value}]",
                 input_action="n/a", output_action="n/a",
                 blocked_by="L3", latency_ms=_ms(t0), action="DENIED",
                 reason=f"denied_code={code.value}: {detail}")
    reply = denials.render(code, user.role, detail=detail,
                           allowed=rbac.get_policy(user.role).summary())
    return {"response": reply,
            "blocked_by": "L3",
            "denied_code": code.value,
            "cia_checks": cia_checks,
            "layers_passed": layers,
            "meta": {"trace": trace, "latency_ms": round(_ms(t0), 1),
                     "secure_mode": SECURE_MODE,
                     "backend": provider.backend_name(),
                     "denied_code": code.value}}


# ---- per-user login (bcrypt + JWT) -----------------------------------------
def _touch_last_login(username: str) -> None:
    try:
        conn = sqlite3.connect(COMPANY_DB)
        conn.execute("UPDATE users SET last_login=CURRENT_TIMESTAMP "
                     "WHERE username=?", (username,))
        conn.commit()
        conn.close()
    except sqlite3.Error:
        pass


def _login_common(username: str, password: str, request: Request) -> dict:
    # S2: brute-force lockout - 5 failures inside 15 min locks the account
    locked, retry = auth.login_lockout((username or "").lower())
    if locked:
        metrics.AI_LOGINS.labels("locked").inc()
        audit.append(user_id=(username or "")[:80], role="-",
                     prompt="(login attempt)", retrieved_context="",
                     ai_response="[locked]", input_action="n/a",
                     output_action="n/a", blocked_by="L1-lockout",
                     latency_ms=0.0, action="DENIED",
                     reason="brute-force lockout active")
        raise HTTPException(429, f"Account temporarily locked. Retry in {retry}s")
    user = auth.authenticate(username, password)
    if not user:
        auth.record_login_failure((username or "").lower())
        metrics.AI_LOGINS.labels("denied").inc()
        audit.append(user_id=(username or "")[:80], role="-",
                     prompt="(login attempt)", retrieved_context="",
                     ai_response="[denied]", input_action="n/a",
                     output_action="n/a", blocked_by="", latency_ms=0.0,
                     action="DENIED", reason="invalid credentials")
        raise HTTPException(401, "Invalid credentials")
    auth.record_login_success(user.username)
    metrics.AI_LOGINS.labels("login").inc()
    exp = int(get_nested(cfg, "session.token_exp_minutes", 60))
    token = auth.issue_token(
        user, get_nested(cfg, "session.jwt_algorithm", "HS256"), exp)
    audit.append(user_id=user.username, role=user.role,
                 prompt="(login)", retrieved_context="",
                 ai_response="[authenticated]", input_action="n/a",
                 output_action="n/a", blocked_by="", latency_ms=0.0,
                 action="LOGIN", reason="bcrypt credentials verified")
    _touch_last_login(user.username)
    return {"access_token": token, "token_type": "bearer",
            "expires_in": exp * 60,
            "user": {"user_id": user.user_id, "username": user.username,
                     "full_name": user.full_name, "role": user.role,
                     "department": user.department,
                     "clearance": user.clearance}}


@app.post("/api/login")
def api_login(req: TokenRequest, request: Request):
    """Per-user login: bcrypt verify -> signed 60-min JWT with
    user_id / username / role / department / clearance / exp claims."""
    return _login_common(req.username, req.password, request)


@app.post("/api/logout")
def logout(request: Request, user: auth.UserCtx = Depends(current_user)):
    """S2 hardening: revoke the presented token's jti immediately. A stolen
    or leaked token can no longer outlive the user's decision to log out."""
    try:
        payload = pyjwt.decode(
            request.headers.get("Authorization", "").removeprefix("Bearer ").strip(),
            options={"verify_signature": False})
        exp = int(payload.get("exp", 0))
    except Exception:
        exp = 0
    auth.revoke_token(user.session_id, exp)
    audit.append(user_id=user.username, role=user.role,
                 prompt="(logout)", retrieved_context="",
                 ai_response="[logged out]", input_action="n/a",
                 output_action="n/a", blocked_by="", latency_ms=0.0,
                 action="LOGOUT", reason="token jti revoked by logout")
    return {"status": "logged_out", "session_id": user.session_id}


# AUTH-08: the legacy /token alias was DELETED. It duplicated the login
# surface (and returned the role in the body) purely for old red-team
# tooling; fewer auth surfaces = fewer bypasses. Tooling now uses /api/login.


# ---- chat (7-layer pipeline + CIA) ------------------------------------------
@app.post("/chat")
@app.post("/api/chat")
def chat(req: ChatRequest, user: auth.UserCtx = Depends(current_user)):
    t0 = time.perf_counter()
    try:
        return _chat_impl(req, user, t0)
    finally:
        metrics.AI_LATENCY.observe(time.perf_counter() - t0)


# ---- S3: global concurrency gate (CIA-A, whole-system) ----------------------
_CHAT_GATE = threading.BoundedSemaphore(
    int(get_nested(cfg, "availability.max_concurrent_chat", 8)))
_MAX_PROMPT_CHARS = int(get_nested(cfg, "availability.max_prompt_chars", 4000))


def _chat_impl(req: ChatRequest, user: auth.UserCtx, t0: float):
    trace: list[dict] = []
    cia_checks = {"confidentiality": "SKIPPED", "integrity": "SKIPPED",
                  "availability": "SKIPPED"}
    layers: list = ["1"]          # CODE-04: layer ids are strings (3.5!)
    op = (req.action_type or "READ").upper()

    # -- L2-size: payload size guard (OWASP LLM10, also CIA-A) --------------
    if len(req.message) > _MAX_PROMPT_CHARS:
        trace.append({"layer": "L2", "check": "payload_size",
                      "result": "blocked",
                      "chars": len(req.message)})
        return _deny(user, req.message[:200], "L2-size",
                     f"prompt exceeds maximum length "
                     f"({len(req.message)} > {_MAX_PROMPT_CHARS} chars)",
                     time.perf_counter() - t0, trace, cia_checks, layers,
                     status_code=413)

    # -- global load gate: no user (or bug) can consume every worker --------
    if not _CHAT_GATE.acquire(blocking=False):
        trace.append({"layer": "L2", "check": "global_concurrency",
                      "result": "429"})
        cia_checks["availability"] = "FAIL"
        metrics.AI_CIA_BLOCKS.labels("A").inc()
        metrics.AI_REQUESTS.labels("rate_limited").inc()
        audit.append(user_id=user.username, role=user.role,
                     prompt=req.message, retrieved_context="",
                     ai_response="[server busy]", input_action="n/a",
                     output_action="n/a", blocked_by="L2-load",
                     latency_ms=round(time.perf_counter() - t0, 1),
                     action="RATE_LIMITED", cia_violation="A",
                     layer_blocked="L2-load",
                     reason="Availability: global concurrency cap reached")
        return JSONResponse(status_code=503, headers={"Retry-After": "5"},
                            content={"response": "Server at capacity. "
                                     "Retry shortly.",
                                     "blocked_by": "L2-load",
                                     "cia_checks": cia_checks,
                                     "layers_passed": layers})
    try:
        deny, bundle = _preflight(req, user, t0, trace, cia_checks, layers, op)
        if deny:
            return deny
        return _finish_query(req, user, t0, trace, cia_checks, layers, bundle)
    finally:
        _CHAT_GATE.release()


def _preflight(req, user, t0, trace, cia_checks, layers, op):
    """Governance pre-flight SHARED by /api/chat and /api/chat/stream:
    L2a rate limit -> CIA-A session cap -> L2b firewall -> CIA-C keyword
    pre-filter -> CIA-I integrity -> L3.5 agency gate -> L3 RBAC ->
    L4 retrieval -> CIA-C data-driven verification.
    Returns (deny_response_or_None, bundle_or_None). One implementation =
    no drift between the JSON and SSE pipelines (CHAT-02)."""
    # -- L2a: unbounded consumption guard (also CIA-A) ---------------------
    est_tokens = max(1, len(req.message) // est_cpt)
    ok, retry, why = limiter.check(user.username, est_tokens)
    trace.append({"layer": "L2", "check": "rate_limit",
                  "result": "pass" if ok else "429"})
    if not ok:
        cia_checks["availability"] = "FAIL"
        metrics.AI_RATE_LIMITED.inc()
        metrics.AI_CIA_BLOCKS.labels("A").inc()
        metrics.AI_REQUESTS.labels("rate_limited").inc()
        audit.append(user_id=user.username, role=user.role, prompt=req.message,
                     retrieved_context="", ai_response="[rate limited]",
                     input_action="rate_limited", output_action="n/a",
                     blocked_by="L2-rate", latency_ms=_ms(t0),
                     action="RATE_LIMITED", cia_violation="A",
                     layer_blocked="L2-rate",
                     reason=f"Availability violation: {why}")
        return JSONResponse(status_code=429,
                            headers={"Retry-After": str(max(retry, 1))},
                            content={
            "response": f"Rate limit exceeded ({why}). Retry in {retry}s.",
            "blocked_by": "L2-rate", "cia_checks": cia_checks,
            "layers_passed": layers}), None
    cia_checks["availability"] = "PASS"
    layers.append("2")

    if SECURE_MODE:
        # -- CIA-A: per-user session cap ------------------------------------
        ok_s, why_s = cia.check_availability(user)
        trace.append({"layer": "CIA-A", "check": "availability",
                      "result": why_s if not ok_s else
                      f"sessions {cia.sessions.active_count(user.username)} "
                      f"ok"})
        if not ok_s:
            return _cia_deny(user, req.message, "A", "CIA-A", why_s,
                             _ms(t0), trace, cia_checks, layers, 429), None

        # -- L2b: input firewall --------------------------------------------
        verdict = input_filter.inspect(req.message, block_score)
        for cat in set(verdict.categories):
            metrics.AI_INPUT_RULES.labels(cat).inc()
        trace.append({"layer": "L2", "check": "input_firewall",
                      "result": verdict.action,
                      "score": verdict.score, "categories": verdict.categories,
                      "ruleset": input_filter.RULESET_VERSION})
        if verdict.action == "block":
            return _deny(user, req.message, "L2",
                         f"prompt-injection pattern detected ({verdict.reason})",
                         _ms(t0), trace, cia_checks, layers,
                         denied_code=ReasonCode.INPUT_BLOCKED), None

        # -- CIA-C: confidentiality (clearance + department isolation) ------
        dept, sensitivity = classify_question(req.message, user.department)
        ok_c, why_c = cia.check_confidentiality(user, "data", dept,
                                                sensitivity)
        trace.append({"layer": "CIA-C", "check": "confidentiality",
                      "result": (why_c if not ok_c else
                                 {"data_domain": dept,
                                  "sensitivity": sensitivity,
                                  "decision": "pass"})})
        if not ok_c:
            cia_checks["confidentiality"] = "FAIL"
            return _cia_deny(user, req.message, "C", "CIA-C", why_c,
                             _ms(t0), trace, cia_checks, layers,
                             denied_code=ReasonCode.CIA_C_DOC), None
        cia_checks["confidentiality"] = "PASS"

        # -- CIA-I: integrity (write operations) -----------------------------
        ok_i, why_i = cia.check_integrity(op, user.role)
        trace.append({"layer": "CIA-I", "check": "integrity",
                      "result": why_i if not ok_i else
                      f"operation {op} allowed for {user.role}"})
        if not ok_i:
            cia_checks["integrity"] = "FAIL"
            return _cia_deny(user, req.message, "I", "CIA-I", why_i,
                             _ms(t0), trace, cia_checks, layers), None
        cia_checks["integrity"] = "PASS"
        if op in WRITE_OPS:
            # Admin write intent: NEVER inline. Convert to a HITL request.
            aid = actions_store.create(
                user_id=user.username, role=user.role,
                source="chat_integrity_gate", action_type=op.lower(),
                target=req.message[:160],
                justification="explicit action_type from an Admin session")
            metrics.AI_ACTIONS.labels("pending").inc()
            metrics.AI_REQUESTS.labels("gated").inc()
            audit.append(user_id=user.username, role=user.role,
                         prompt=req.message, retrieved_context="",
                         ai_response=f"[L3.5 gated -> pending action #{aid}]",
                         input_action="gated", output_action="n/a",
                         blocked_by="L3.5", latency_ms=_ms(t0),
                         action="BLOCKED", cia_violation=None,
                         layer_blocked="L3.5",
                         reason="write operation routed to HITL approval")
            layers.append("3.5")
            return {
                "response": (
                    f"Action Pending: '{req.message[:120]}'. The assistant "
                    f"cannot execute write operations (OWASP LLM03: "
                    f"Excessive Agency). Request #{aid} was created and is "
                    f"waiting for approval by {sorted(APPROVER_ROLES)} via "
                    f"POST /api/action/confirm/{aid}."),
                "blocked_by": "L3.5",
                "cia_checks": cia_checks,
                "layers_passed": layers,
                "action_request": {"id": aid, "status": "pending",
                                   "action_type": op.lower(),
                                   "target": req.message[:160],
                                   "source": "chat_integrity_gate"},
                "meta": {"trace": trace, "latency_ms": round(_ms(t0), 1),
                         "secure_mode": SECURE_MODE,
                         "backend": provider.backend_name()}}, None

        # -- L3.5: excessive-agency gate (HITL) -------------------------------
        # The AI never executes high-risk actions. A risky request becomes a
        # PENDING ACTION REQUEST that an authorised human must confirm.
        intent = actions.detect(req.message)
        trace.append({"layer": "L3.5", "check": "excessive_agency_gate",
                      "result": ("blocked (pending HITL approval)"
                                 if intent else "pass")})
        layers.append("3.5")
        if intent:
            aid = actions_store.create(
                user_id=user.username, role=user.role,
                source="chat_auto_gate", action_type=intent.action_type,
                target=intent.target,
                justification="auto-detected by the Layer 3.5 agency gate")
            metrics.AI_BLOCKED.labels("L3.5").inc()
            metrics.AI_REQUESTS.labels("gated").inc()
            metrics.AI_ACTIONS.labels("pending").inc()
            audit.append(user_id=user.username, role=user.role,
                         prompt=req.message, retrieved_context="",
                         ai_response=f"[L3.5 gated -> pending action #{aid}]",
                         input_action="gated", output_action="n/a",
                         blocked_by="L3.5", latency_ms=_ms(t0),
                         action="BLOCKED", layer_blocked="L3.5",
                         reason=f"high-risk action '{intent.action_type}' "
                                f"requires human approval")
            return {
                "response": (
                    f"Action Pending: '{intent.target}'. The assistant cannot "
                    f"execute high-risk actions (OWASP LLM03: Excessive "
                    f"Agency). Request #{aid} was created and is waiting for "
                    f"approval by {sorted(APPROVER_ROLES)} via "
                    f"POST /api/action/confirm/{aid}."),
                "blocked_by": "L3.5",
                "cia_checks": cia_checks,
                "layers_passed": layers,
                "action_request": {"id": aid, "status": "pending",
                                   "action_type": intent.action_type,
                                   "target": intent.target,
                                   "source": "chat_auto_gate"},
                "meta": {"trace": trace, "latency_ms": round(_ms(t0), 1),
                         "secure_mode": SECURE_MODE,
                         "backend": provider.backend_name()}}, None

    else:
        trace.append({"layer": "L2", "check": "input_firewall",
                      "result": "DISABLED (baseline mode)"})

    # -- L3: RBAC policy resolution ---------------------------------------
    policy = rbac.get_policy(user.role)
    trace.append({"layer": "L3", "check": "rbac_resolve",
                  "result": {"tables": policy.allowed_tables,
                             "namespaces": policy.allowed_namespaces}})
    layers.append("3")

    if SECURE_MODE:
        # -- L3+: field-intent authorisation (Denial Engine, Wave 1.1) ------
        # A question that explicitly targets a restricted FIELD (a
        # colleague's salary, someone's bonus) is refused with an official,
        # constructive denial BEFORE retrieval: the model never sees a
        # context missing the requested field, so it cannot hallucinate
        # around the gap, and the user gets policy citation + 'You can
        # view' + escalation path instead of a soft dead end.
        violation = rbac.field_intent_violation(policy, req.message)
        if violation:
            fld, detail = violation
            return _authz_deny(req, user, ReasonCode.AUTHZ_FIELD,
                               detail, t0, trace, cia_checks, layers), None
        trace.append({"layer": "L3", "check": "field_intent_authorised",
                      "result": "pass"})

    # -- L4: scoped retrieval ---------------------------------------------
    try:
        bundle = retriever.retrieve(policy, req.message, store)
    except rbac.PermissionDenied as exc:
        # Defensive: the intent router pre-filters tables, so this only
        # fires if a future call site passes a non-granted table. Fail the
        # same OFFICIAL way (Denial Engine), never with a 500.
        return _authz_deny(req, user, exc.code, exc.detail, t0, trace,
                           cia_checks, layers), None
    trace.append({"layer": "L4", "check": "scoped_retrieval",
                  "result": {"tables_queried": bundle["tables_queried"],
                             "namespaces_searched": bundle["namespaces_searched"],
                             "rows": bundle["n_rows"], "docs": bundle["n_docs"]}})
    layers.append("4")

    if SECURE_MODE:
        # -- CIA-C (data-driven verification, CHAT-06): the keyword
        # classifier above is only a FAST-PATH pre-filter. The authoritative
        # check reads the sensitivity/department metadata of the documents
        # actually retrieved - so a synonym that slips past the keyword list
        # ('income', 'pay', 'CTC'...) is still stopped here when the matched
        # document is above the user's clearance or outside their department.
        ok_cd, why_cd = cia.check_retrieved_docs(user, bundle.get("sources", []))
        trace.append({"layer": "CIA-C", "check": "retrieved_document_meta",
                      "result": why_cd if not ok_cd else "pass"})
        if not ok_cd:
            cia_checks["confidentiality"] = "FAIL"
            return _cia_deny(user, req.message, "C", "CIA-C-data", why_cd,
                             _ms(t0), trace, cia_checks, layers,
                             denied_code=ReasonCode.CIA_C_DOC), None

    return None, bundle


def _finish_query(req, user, t0, trace, cia_checks, layers, bundle):
    """L5 model + L6 output governance + L7 audit - the synchronous tail of
    the pipeline (the SSE variant re-implements L5/L6 incrementally)."""
    # -- L5: model inference -----------------------------------------------
    user_turn = build_user_turn(req.message, bundle["context"])
    gen = provider.generate(req.message, bundle["context"], user_turn)
    raw = gen.text
    trace.append({"layer": "L5", "check": "model_inference",
                  "result": {"backend": gen.backend,
                             "degraded": gen.degraded,
                             "chars": len(raw)}})
    layers.append("5")
    if gen.degraded:
        # CHAT-01: never degrade silently - the reply body itself carries
        # the notice, and the meta carries the machine-readable flag.
        raw = provider.DEGRADED_BANNER.format(
            reason=gen.reason[:80]) + raw

    # -- L6: output governance ----------------------------------------------
    if SECURE_MODE:
        out = output_filter.check(raw, bundle["context"], user.role)
        trace.append({"layer": "L6", "check": "dlp_faithfulness",
                      "result": out.action, "reasons": out.reasons})
        if out.action == "block":
            metrics.AI_REDACTIONS.inc()
            metrics.AI_BLOCKED.labels("L6").inc()
            metrics.AI_REQUESTS.labels("blocked").inc()
            audit.flag_for_review(user_id=user.username, role=user.role,
                                  prompt=req.message, withheld=raw[:2000],
                                  reason=out.summary)
            return _deny(user, req.message, "L6",
                         "potential sensitive-data disclosure, unfaithful "
                         "output, or indirect-injection residue; response "
                         "withheld for human review", _ms(t0), trace,
                         cia_checks, layers,
                         denied_code=ReasonCode.DLP_OUTPUT)
        final = out.text
        layers.append("6")
    else:
        final = raw
        trace.append({"layer": "L6", "check": "dlp_faithfulness",
                      "result": "DISABLED (baseline mode)"})

    # -- L7: audit -----------------------------------------------------------
    audit.append(user_id=user.username, role=user.role, prompt=req.message,
                 retrieved_context=bundle["context"][:1000],
                 ai_response=final, input_action="allow",
                 output_action="allow", blocked_by="",
                 latency_ms=_ms(t0), action="QUERY")
    metrics.AI_REQUESTS.labels("allow").inc()
    trace.append({"layer": "L7", "check": "audit_chain", "result": "appended"})
    layers.append("7")
    return {"response": final,
            "cia_checks": cia_checks,
            "layers_passed": layers,
            "blocked_by": None,
            "sources": bundle.get("sources", []),
            "meta": {"trace": trace, "latency_ms": round(_ms(t0), 1),
                     "secure_mode": SECURE_MODE,
                     "backend": gen.backend,
                     "degraded": gen.degraded}}


def _ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000


# ---- CHAT-02: SSE streaming variant (same governance, progressive output) --
def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


_STREAM_FLUSH = re.compile(r"(?<=[.!?])\s+|\n")


@app.post("/api/chat/stream")
def chat_stream(req: ChatRequest, user: auth.UserCtx = Depends(current_user)):
    """Server-Sent Events chat. Governance is IDENTICAL to /api/chat (the
    same _preflight code runs) - only L5/L6 differ:

    - L5 tokens stream as 'delta' events (Ollama native stream; the mock
      model is chunked word-by-word so the UX is testable offline);
    - L6 runs INCREMENTALLY: each completed sentence is shape-redacted
      before it is flushed to the client, and hard leak indicators
      (canary / system-prompt marks / injection residue / secret shapes)
      abort the stream immediately;
    - at the end the FULL accumulated text runs the complete Layer 6 check
      (faithfulness included). If it fails, a 'revoked' event instructs the
      client to replace everything with the official block - nothing
      sensitive was left on screen un-governed.

    Events: meta -> delta* -> (final | revoked | blocked)."""
    t0 = time.perf_counter()

    def event_stream():
        trace: list[dict] = []
        cia_checks = {"confidentiality": "SKIPPED", "integrity": "SKIPPED",
                      "availability": "SKIPPED"}
        layers: list = ["1"]
        op = (req.action_type or "READ").upper()

        # -- L2-size (identical to the sync path) ---------------------------
        if len(req.message) > _MAX_PROMPT_CHARS:
            trace.append({"layer": "L2", "check": "payload_size",
                          "result": "blocked", "chars": len(req.message)})
            body, code = _deny(user, req.message[:200], "L2-size",
                               f"prompt exceeds maximum length "
                               f"({len(req.message)} > {_MAX_PROMPT_CHARS} chars)",
                               time.perf_counter() - t0, trace, cia_checks,
                               layers, status_code=200), 413
            yield _sse("blocked", body)
            return

        if not _CHAT_GATE.acquire(blocking=False):
            metrics.AI_REQUESTS.labels("rate_limited").inc()
            yield _sse("blocked", {"response": "Server at capacity. "
                                   "Retry shortly.",
                                   "blocked_by": "L2-load",
                                   "cia_checks": cia_checks,
                                   "layers_passed": layers})
            return
        try:
            deny, bundle = _preflight(req, user, t0, trace, cia_checks,
                                      layers, op)
            if deny:
                body = deny
                if hasattr(deny, "body"):     # JSONResponse -> dict for SSE
                    body = json.loads(deny.body)
                yield _sse("blocked", body)
                return

            yield _sse("meta", {"layers_passed": layers,
                                "cia_checks": cia_checks,
                                "sources": bundle.get("sources", []),
                                "backend": provider.backend_name()})

            # -- L5 (streaming) + L6 (incremental + final) ------------------
            user_turn = build_user_turn(req.message, bundle["context"])
            emitted: list[str] = []       # sentences actually flushed
            pending = ""                  # unflushed tail (never trusted)
            degraded_reason = ""
            hard_abort: list[str] = []

            def hard_check(text: str) -> list[str]:
                """Hard-only L6 subset detectable mid-stream."""
                return output_filter.hard_reasons(text, user.role)

            def chunk_source():
                if provider.backend_name() == "ollama":
                    try:
                        yield from ollama_model.generate_stream(
                            provider.SYSTEM_PROMPT, user_turn)
                        return
                    except ollama_model.ProviderUnavailable as exc:
                        nonlocal degraded_reason
                        degraded_reason = str(exc)[:120]
                        yield provider.DEGRADED_BANNER.format(
                            reason=degraded_reason[:80])
                text = mock_model.generate(req.message, bundle["context"])
                for word in text.split(" "):
                    yield word + " "
                    time.sleep(0.012)

            gen_backend = provider.backend_name()
            try:
                for piece in chunk_source():
                    pending += piece
                    # flush completed sentences; the tail stays unflushed
                    # until a boundary arrives (never trust the last line)
                    while True:
                        m = _STREAM_FLUSH.search(pending)
                        if not m:
                            break
                        sentence = pending[: m.end()]
                        pending = pending[m.end():]
                        hard = hard_check(sentence)
                        if hard:
                            hard_abort = hard
                            break
                        red = output_filter.redact(sentence, user.role)
                        emitted.append(red.text)
                        yield _sse("delta", {"t": red.text})
                    if hard_abort:
                        break
            except ollama_model.ProviderUnavailable as exc:
                degraded_reason = degraded_reason or str(exc)[:120]
                yield _sse("delta", {"t": provider.DEGRADED_BANNER.format(
                    reason=degraded_reason[:80])})
                text = mock_model.generate(req.message, bundle["context"])
                emitted.append(text)
                yield _sse("delta", {"t": text})

            if hard_abort:
                # hard leak indicator mid-stream: revoke everything
                audit.flag_for_review(user_id=user.username, role=user.role,
                                      prompt=req.message,
                                      withheld="".join(emitted)[:2000],
                                      reason="; ".join(hard_abort))
                deny_body = json.loads(_deny(
                    user, req.message, "L6",
                    "stream revoked: " + "; ".join(hard_abort),
                    time.perf_counter() - t0, trace, cia_checks, layers,
                    status_code=200).body)
                yield _sse("revoked", deny_body)
                return

            full_text = "".join(emitted) + pending
            if degraded_reason:
                full_text = provider.DEGRADED_BANNER.format(
                    reason=degraded_reason[:80]) + full_text
            out = output_filter.check(full_text, bundle["context"], user.role)
            trace.append({"layer": "L6", "check": "dlp_faithfulness",
                          "result": out.action, "reasons": out.reasons})
            if out.action == "block":
                audit.flag_for_review(user_id=user.username, role=user.role,
                                      prompt=req.message,
                                      withheld=full_text[:2000],
                                      reason=out.summary)
                deny_body = json.loads(_deny(
                    user, req.message, "L6",
                    "potential sensitive-data disclosure, unfaithful output, "
                    "or indirect-injection residue; streamed response "
                    "revoked for human review", time.perf_counter() - t0,
                    trace, cia_checks, layers, status_code=200).body)
                yield _sse("revoked", deny_body)
                return

            audit.append(user_id=user.username, role=user.role,
                         prompt=req.message,
                         retrieved_context=bundle["context"][:1000],
                         ai_response=out.text or full_text,
                         input_action="allow", output_action="allow",
                         blocked_by="", latency_ms=_ms(t0), action="QUERY")
            metrics.AI_REQUESTS.labels("allow").inc()
            trace.append({"layer": "L7", "check": "audit_chain",
                          "result": "appended"})
            layers.append("6")
            layers.append("7")
            yield _sse("final", {"response": out.text or full_text,
                                 "blocked_by": None,
                                 "cia_checks": cia_checks,
                                 "layers_passed": layers,
                                 "sources": bundle.get("sources", []),
                                 "meta": {"trace": trace,
                                          "latency_ms": round(_ms(t0), 1),
                                          "secure_mode": SECURE_MODE,
                                          "backend": gen_backend,
                                          "degraded": bool(degraded_reason)}})
        finally:
            _CHAT_GATE.release()
            metrics.AI_LATENCY.observe(time.perf_counter() - t0)

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


# ---- HITL: pending-action lifecycle (OWASP LLM03 / NIST Manage) ----------
def _require_roles(user, allowed):
    if user.role not in allowed:
        raise HTTPException(403, f"requires one of {sorted(allowed)}")


@app.post("/api/action/request")
def action_request(req: ActionRequestBody,
                   user: auth.UserCtx = Depends(current_user)):
    """Explicitly submit a high-risk action for human approval. Any
    authenticated user may REQUEST; only approver roles may CONFIRM."""
    if not req.action_type or not req.target:
        raise HTTPException(422, "action_type and target are required")
    aid = actions_store.create(
        user_id=user.username, role=user.role, source="api_request",
        action_type=req.action_type, target=req.target,
        justification=req.justification[:300])
    metrics.AI_ACTIONS.labels("pending").inc()
    audit.append(user_id=user.username, role=user.role,
                 prompt=f"ACTION REQUEST #{aid}: {req.action_type} {req.target}",
                 retrieved_context="", ai_response="[created, pending approval]",
                 input_action="action_requested", output_action="n/a",
                 blocked_by="", latency_ms=0.0, action="QUERY",
                 reason="explicit HITL action request")
    return {"status": "pending", "action_request":
            {"id": aid, "status": "pending", "action_type": req.action_type,
             "target": req.target, "requested_by": user.username,
             "source": "api_request"},
            "message": (f"Action Pending: '{req.target}'. Waiting for approval "
                        f"by {sorted(APPROVER_ROLES)} via "
                        f"POST /api/action/confirm/{aid}.")}


@app.get("/api/action/list")
def action_list(user: auth.UserCtx = Depends(current_user)):
    _require_roles(user, APPROVER_ROLES)
    return {"open_actions": actions_store.list_open(),
            "approver_roles": sorted(APPROVER_ROLES)}


@app.post("/api/action/confirm/{request_id}")
def action_confirm(request_id: int,
                   user: auth.UserCtx = Depends(current_user)):
    """Approve AND execute atomically (CODE-01): claim() transitions the
    request to 'executing' inside the lock, so two concurrent confirms can
    never both execute; the requester can never approve their own request
    (segregation of duties, enforced); expired requests are rejected."""
    _require_roles(user, APPROVER_ROLES)
    rec = actions_store.get(request_id)
    if not rec:
        raise HTTPException(404, f"action request #{request_id} not found")
    if rec["status"] != "pending":
        raise HTTPException(409, f"action request #{request_id} is already "
                                 f"'{rec['status']}'")
    if rec["user_id"] == user.username:
        metrics.AI_ACTIONS.labels("rejected").inc()
        audit.append(user_id=user.username, role=user.role,
                     prompt=f"ACTION #{request_id} self-approval attempt",
                     retrieved_context="", ai_response="[denied]",
                     input_action="n/a", output_action="n/a",
                     blocked_by="L3.5", latency_ms=0.0, action="DENIED",
                     reason="segregation of duties: requester != approver")
        raise HTTPException(403, "segregation of duties: you cannot approve "
                                 "your own action request")
    claimed = actions_store.claim(request_id)
    if not claimed:
        raise HTTPException(409, f"action request #{request_id} is no longer "
                                 f"claimable (decided, executing or expired)")
    result = actions.sandboxed_execute(claimed)
    rec = actions_store.finalise(request_id, approve=True,
                                 decider=user.username,
                                 result=json.dumps(result)[:500])
    metrics.AI_ACTIONS.labels("approved").inc()
    audit.append(user_id=user.username, role=user.role,
                 prompt=f"ACTION #{request_id} approved: {rec['action_type']} "
                        f"on '{rec['target']}'",
                 retrieved_context="", ai_response=json.dumps(result)[:500],
                 input_action="action_approved", output_action="n/a",
                 blocked_by="", latency_ms=0.0, action="APPROVED",
                 reason="HITL approval executed in read-only sandbox")
    return {"status": "approved", "action_id": request_id,
            "decided_by": user.username, "execution": result}


@app.post("/api/action/reject/{request_id}")
def action_reject(request_id: int,
                  user: auth.UserCtx = Depends(current_user)):
    _require_roles(user, APPROVER_ROLES)
    rec = actions_store.get(request_id)
    if not rec:
        raise HTTPException(404, f"action request #{request_id} not found")
    if rec["status"] != "pending":
        raise HTTPException(409, f"action request #{request_id} is already "
                                 f"'{rec['status']}'")
    actions_store.resolve(request_id, approve=False, decider=user.username,
                          result="rejected by approver")
    metrics.AI_ACTIONS.labels("rejected").inc()
    audit.append(user_id=user.username, role=user.role,
                 prompt=f"ACTION #{request_id} rejected: {rec['action_type']} "
                        f"on '{rec['target']}'",
                 retrieved_context="", ai_response="[rejected]",
                 input_action="action_rejected", output_action="n/a",
                 blocked_by="", latency_ms=0.0, action="DENIED",
                 reason="HITL request rejected by approver")
    return {"status": "rejected", "action_id": request_id,
            "decided_by": user.username}


# ---- identity & per-user audit surfaces ------------------------------------
@app.get("/api/me")
def me(user: auth.UserCtx = Depends(current_user)):
    """Who am I: profile + effective access posture for this session."""
    prof = auth.profile(user.username)
    pol = rbac.get_policy(user.role)
    return {"user": {**prof,
                     "clearance": user.clearance or prof.get("clearance")},
            "effective_access": {"tables": pol.allowed_tables,
                                 "namespaces": pol.allowed_namespaces},
            "session": {"jti": user.session_id,
                        "active_sessions":
                            cia.sessions.active_count(user.username)}}


@app.get("/api/audit/me")
def audit_me(limit: int = 100,
             user: auth.UserCtx = Depends(current_user)):
    """My own audit trail (every allow and every block, hash-chained).
    DASH-05: limit clamped so one client cannot pull an unbounded trail."""
    limit = max(1, min(limit, 500))
    return {"events": audit.for_user(user.username, limit),
            "blocked_attempts": audit.blocked_for_user(user.username)}


@app.get("/api/audit/all")
def audit_all(limit: int = 100,
              user: auth.UserCtx = Depends(current_user)):
    """Admin-only: the full system audit trail. DASH-05: limit clamped to
    500; the response carries the total for cursor-style paging."""
    _require_roles(user, ADMIN_ROLES)
    limit = max(1, min(limit, 500))
    events = [{**e, "event_id": e["id"]} for e in audit.recent(limit)]
    return {"events": events, "total": audit.stats()["total_events"],
            "chain_verified": audit.verify()[0],
            "stats": audit.stats()}


@app.get("/api/stats")
def stats(user: auth.UserCtx = Depends(current_user)):
    """Admin-only: system-wide governance stats for the dashboard."""
    _require_roles(user, ADMIN_ROLES)
    return {**audit.stats(), "chain_verified": audit.verify()[0],
            "pending_actions": len(actions_store.list_open()),
            "active_backend": provider.backend_name(),
            "secure_mode": SECURE_MODE}


# ---- admin / governance surfaces (Executive & HR only) -------------------
@app.get("/admin/audit")
def admin_audit(limit: int = 50,
                user: auth.UserCtx = Depends(current_user)):
    _require_roles(user, {"Executive", "HR_Manager"} | ADMIN_ROLES)
    limit = max(1, min(limit, 500))          # DASH-05: bounded responses
    return {"events": audit.recent(limit),
            "chain_verified": audit.verify()[0]}


@app.get("/admin/audit/verify")
def admin_verify(user: auth.UserCtx = Depends(current_user)):
    _require_roles(user, {"Executive", "HR_Manager"} | ADMIN_ROLES)
    ok, bad = audit.verify()
    return {"chain_valid": ok, "first_bad_id": bad}


@app.get("/admin/review")
def review_list(user: auth.UserCtx = Depends(current_user)):
    _require_roles(user, {"Executive", "HR_Manager"} | ADMIN_ROLES)
    return {"open_items": audit.review_list()}


@app.post("/admin/review/{item_id}/release")
def review_release(item_id: int, user: auth.UserCtx = Depends(current_user)):
    _require_roles(user, {"Executive", "HR_Manager"} | ADMIN_ROLES)
    text = audit.review_resolve(item_id, release=True)
    return {"released": text is not None, "withheld_response": text}


@app.post("/admin/review/{item_id}/reject")
def review_reject(item_id: int, user: auth.UserCtx = Depends(current_user)):
    _require_roles(user, {"Executive", "HR_Manager"} | ADMIN_ROLES)
    audit.review_resolve(item_id, release=False)
    return {"released": False}


# ---- operations: health & metrics (CIA "Availability") --------------------
def _ro_count(db: Path, sql: str):
    try:
        return sqlite3.connect(f"file:{db}?mode=ro", uri=True).execute(sql)\
            .fetchone()[0]
    except Exception:
        return None


@app.get("/health")
def health():
    """Minimal PUBLIC liveness probe (DASH-04): status + version + model
    reachability only. Row counts, secure-mode posture, Ollama URL and the
    audit-chain state now live behind Admin auth at /admin/posture - an
    unauthenticated scraper no longer learns the deployment's internals."""
    return {
        "status": "healthy",
        "version": app.version,
        "uptime_s": round(time.time() - _START_TIME, 1),
        "model_backend": provider.backend_name(),
        "ollama_reachable": provider.status()["ollama_reachable"],
    }


@app.get("/admin/posture")
def admin_posture(user: auth.UserCtx = Depends(current_user)):
    """Admin-only deep posture probe (was the public /health body, DASH-04):
    model backend detail, data-store counts, tamper-evidence state, HITL
    depth and the vector namespace inventory."""
    _require_roles(user, ADMIN_ROLES)
    chain_ok, _bad = audit.verify_cached()
    st = provider.status()
    return {
        "status": "healthy",
        "version": app.version,
        "uptime_s": round(time.time() - _START_TIME, 1),
        "secure_mode": SECURE_MODE,
        "model": {**st,
                  "ollama_url": get_nested(cfg, "model.ollama_url",
                                           "http://localhost:11434"),
                  "ollama_model": get_nested(cfg, "model.ollama_model",
                                             "qwen2.5:0.5b")},
        "databases": {
            "company_employees": _ro_count(COMPANY_DB,
                                           "SELECT COUNT(*) FROM employees"),
            "users": _ro_count(COMPANY_DB, "SELECT COUNT(*) FROM users"),
            "documents": _ro_count(COMPANY_DB,
                                   "SELECT COUNT(*) FROM documents"),
            "executives": _ro_count(EXECUTIVES_DB,
                                    "SELECT COUNT(*) FROM executives"),
            "audit_events": _ro_count(AUDIT_DB,
                                      "SELECT COUNT(*) FROM audit"),
            "audit_chain_valid": chain_ok,
            "pending_actions": len(actions_store.list_open()),
            "open_review_items": len(audit.review_list()),
        },
        "vector_namespaces": store.namespaces(),
    }


@app.get("/metrics")
def metrics_endpoint(request: Request):
    """Prometheus text exposition, served directly (no trailing slash
    needed). /metrics/ additionally works via the mounted ASGI app below,
    so both scraper conventions succeed. DASH-04: when METRICS_TOKEN is
    configured, scrapers must present it as 'Authorization: Bearer <tok>'
    (or ?token=) - posture counters are no longer world-readable."""
    if METRICS_TOKEN:
        supplied = ""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            supplied = auth_header.removeprefix("Bearer ").strip()
        supplied = supplied or request.query_params.get("token", "")
        if not secrets.compare_digest(supplied, METRICS_TOKEN):
            raise HTTPException(401, "metrics scrape token required")
    return Response(content=generate_latest(metrics.REG),
                    media_type=CONTENT_TYPE_LATEST)


# Prometheus exposition (mounted BEFORE the static UI catch-all).
# The wrapper rewrites the child path so /metrics/<anything> also serves.
class _MetricsAtRoot:
    def __init__(self, inner):
        self._inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") != "/":
            scope = dict(scope, path="/")
        await self._inner(scope, receive, send)


app.mount("/metrics", _MetricsAtRoot(make_asgi_app(registry=metrics.REG)),
          name="metrics")


# ---- UI pages (login + dashboard + single-file chat demo) ------------------
_static = PROJECT_ROOT / "src" / "api" / "static"


@app.get("/login", include_in_schema=False)
def login_page():
    return FileResponse(_static / "login.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard_page():
    return FileResponse(_static / "dashboard.html")


if _static.exists():
    app.mount("/", StaticFiles(directory=_static, html=True), name="ui")
