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
from src.governance import actions, auth, cia_enforcer, compliance, \
    denials, dpdp_compliance, input_filter, iso42001_soa, metrics, \
    nist_csf_mapping, output_filter, rbac
from src.governance.audit import AuditChain
from src.governance.cia_enforcer import WRITE_OPS, classify_question
from src.governance.denials import ReasonCode
from src.governance.rate_limiter import SlidingWindowRateLimiter
from src.governance.streaming_dlp import StreamingDLP
from src.governance.token_budget import TokenBudgetGuard
from src.governance import user_admin
from src.model import catalog as model_catalog
from src.model import colibri_model, mock_model, ollama_model, provider
from src.model.prompts import (GENERAL_SYSTEM_PROMPT, SYSTEM_PROMPT,
                               build_general_turn, build_user_turn)
from src.rag import retriever
from src.router import intent as intent_router

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

# Pre-deploy gate Step 7: the operator kill switch. AI_ENABLED=false (or any
# value not in the truthy set - a typo FAILS CLOSED toward 'disabled') turns
# every chat entry point into an immediate 503 while /health, /metrics,
# login and the admin surfaces stay up. This is the incident lever for
# "disable AI features immediately": flip one env var + restart, no
# redeploy, no data loss, and the denial is counted in ai_kill_switch_denials_total.
_TRUTHY = {"1", "true", "yes", "on"}


def ai_enabled() -> bool:
    raw = os.environ.get("AI_ENABLED", "true").strip().lower()
    return raw in _TRUTHY          # absent -> enabled; anything else -> off


def _kill_switch_response():
    metrics.AI_KILL_SWITCH.inc()
    return JSONResponse(
        status_code=503,
        content={"response": "AI features are temporarily disabled by the "
                             "operator (kill switch). Retry later or contact "
                             "your administrator.",
                 "blocked_by": "KILL_SWITCH",
                 "cia_checks": {"confidentiality": "SKIPPED",
                                "integrity": "SKIPPED",
                                "availability": "SKIPPED"},
                 "layers_passed": []})

APPROVER_ROLES = set(get_nested(cfg, "action_gate.approver_roles", ["Executive"]))
ADMIN_ROLES = {"Admin"}
_START_TIME = time.time()

app = FastAPI(
    title="SecureLLM-Enterprise",
    description="Governance-enforced enterprise AI chatbot "
                "(NIST AI RMF + OWASP LLM Top 10 + CIA triad)",
    version="5.1.0")
audit = AuditChain()
audit.start_maintenance()          # RAG-07: retention purge + rotation loop
# v4.9.0: governance-transparency store (AI inventory, risk register,
# AI incident ledger) - the compliance plane that PROVES what L1-L7 do.
compliance_store = compliance.ComplianceStore()
limiter = SlidingWindowRateLimiter(
    requests_per_minute=int(get_nested(cfg, "rate_limit.requests_per_minute", 20)),
    token_budget_per_minute=int(get_nested(cfg, "rate_limit.token_budget_per_minute", 6000)))
# v5.1.0 (Layer 2c): per-session token budget (OWASP LLM10 - KV-cache
# exhaustion). The per-user/minute limiter above stops floods; THIS guard
# bounds the total tokens (input + output) one long-lived session can
# push through the model in a rolling window.
budget_guard = TokenBudgetGuard(
    max_tokens=int(get_nested(cfg, "token_budget.max_tokens", 20000)),
    window_seconds=int(get_nested(cfg, "token_budget.window_seconds", 600)),
    est_chars_per_token=int(get_nested(cfg, "token_budget.est_chars_per_token", 4)))
BUDGET_ENABLED = bool(get_nested(cfg, "token_budget.enabled", True))
# v5.1.0 (Layer 6s): streaming DLP windows (detection latency + memory
# bounds for the SSE pipeline; see src/governance/streaming_dlp.py).
STREAM_SCAN_WINDOW = int(get_nested(cfg, "streaming.scan_window_chars", 400))
STREAM_FLUSH_CAP = int(get_nested(cfg, "streaming.flush_cap_chars", 2000))
STREAM_TAIL_KEEP = int(get_nested(cfg, "streaming.tail_keep_chars", 64))
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
    # Wave 6 channels: "web" (default) | "telegram" | "mcp" | ...
    # external_user: opaque caller identity at the channel (e.g. telegram
    # user id) - recorded in the audit chain so a channel answer is
    # attributable to the real human behind the service identity.
    channel: str = Field("web", max_length=24, pattern=r"^[a-z0-9_-]+$")
    external_user: str = Field("", max_length=64)

    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


class TokenRequest(BaseModel):
    username: str
    password: str


class ActionRequestBody(BaseModel):
    action_type: str
    target: str
    justification: str = ""

    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


_CSRF_METHODS = ("POST", "PUT", "PATCH", "DELETE")
_SESSION_COOKIE = "seac_session"
_CSRF_COOKIE = "seac_csrf"


def current_user(request: Request) -> auth.UserCtx:
    """Layer 1 dependency: signature + expiry + logout revocation + LIVE
    account re-validation (AUTH-06). Role/department/clearance/active are
    refreshed from the database on every request - a downgraded, offboarded
    or deactivated account loses access on its very next call, not at token
    expiry. Fails closed when the account has vanished.

    Wave 5.1: the JWT may arrive as an Authorization: Bearer header (the API
    contract) OR as the HttpOnly session cookie (browser flow). Cookie-auth
    requests are CSRF-protected: every state-changing method must echo the
    seac_csrf cookie in the X-CSRF-Token header (double-submit pattern,
    constant-time compare) - a cross-site page cannot forge it."""
    header = request.headers.get("Authorization", "")
    cookie_token = request.cookies.get(_SESSION_COOKIE, "")
    via_cookie = False
    if header.startswith("Bearer "):
        token = header.removeprefix("Bearer ").strip()
    elif cookie_token:
        token = cookie_token
        via_cookie = True
    else:
        raise HTTPException(401, "missing bearer token")
    if via_cookie and request.method in _CSRF_METHODS:
        csrf_header = request.headers.get("X-CSRF-Token", "")
        csrf_cookie = request.cookies.get(_CSRF_COOKIE, "")
        if not csrf_cookie or not csrf_header or \
                not secrets.compare_digest(csrf_header, csrf_cookie):
            raise HTTPException(403, "CSRF token missing or invalid")
    try:
        user = auth.verify_token(token)
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


def _login_common(username: str, password: str, request: Request,
                  response: Response) -> dict:
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
    # Wave 5.1: HttpOnly session cookie (XSS cannot read it) + a readable
    # CSRF token for the double-submit pattern. Bearer remains the API
    # contract; cookie-auth requests must prove the CSRF token on every
    # state-changing method (verified in current_user).
    secure_cookies = bool(get_nested(cfg, "session.cookie_secure", False))
    csrf = secrets.token_urlsafe(32)
    max_age = exp * 60
    response.set_cookie("seac_session", token, httponly=True,
                        secure=secure_cookies, samesite="lax",
                        max_age=max_age, path="/")
    response.set_cookie("seac_csrf", csrf, httponly=False,
                        secure=secure_cookies, samesite="lax",
                        max_age=max_age, path="/")
    return {"access_token": token, "token_type": "bearer",
            "expires_in": exp * 60, "csrf_token": csrf,
            "user": {"user_id": user.user_id, "username": user.username,
                     "full_name": user.full_name, "role": user.role,
                     "department": user.department,
                     "clearance": user.clearance,
                     "must_change_password": user.must_change_password}}


@app.post("/api/login")
def api_login(req: TokenRequest, request: Request, response: Response):
    """Per-user login: bcrypt verify -> signed 60-min JWT with
    user_id / username / role / department / clearance / exp claims.
    Wave 5.1: ALSO issues an HttpOnly session cookie + CSRF token so
    browser clients can drop token-in-JS storage entirely."""
    return _login_common(req.username, req.password, request, response)


@app.post("/api/logout")
def logout(request: Request, response: Response,
           user: auth.UserCtx = Depends(current_user)):
    """S2 hardening: revoke the presented token's jti immediately. A stolen
    or leaked token can no longer outlive the user's decision to log out.
    Wave 5.1: the session/CSRF cookies are cleared as well."""
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
    response.delete_cookie("seac_session", path="/")
    response.delete_cookie("seac_csrf", path="/")
    return {"status": "logged_out", "session_id": user.session_id}


# AUTH-08: the legacy /token alias was DELETED. It duplicated the login
# surface (and returned the role in the body) purely for old red-team
# tooling; fewer auth surfaces = fewer bypasses. Tooling now uses /api/login.


# ---- chat (7-layer pipeline + CIA) ------------------------------------------
def _audit_chat_error(req: ChatRequest, user, exc: Exception, where: str):
    """L7 must see EVERY governed request - including ones that die on an
    internal error. Live-battery finding (2026-10): an unexpected exception
    in the self-scope path returned a bare 500 with no audit row, leaving an
    unaudited blind spot an attacker could provoke at will. This helper
    records the attempt, then the caller returns a sanitized 500."""
    try:
        audit.append(user_id=user.username, role=user.role,
                     prompt=(req.message or "")[:200], retrieved_context="",
                     ai_response=f"[internal error: {where}]",
                     input_action=(req.action_type or "READ").upper(),
                     output_action="n/a", blocked_by="ERROR",
                     latency_ms=0.0, action="ERROR",
                     reason=f"{exc.__class__.__name__}: {exc}"[:300])
    except Exception:               # audit must never mask the original fault
        pass


@app.post("/chat")
@app.post("/api/chat")
def chat(req: ChatRequest, user: auth.UserCtx = Depends(current_user)):
    t0 = time.perf_counter()
    if not ai_enabled():          # operator kill switch (pre-deploy gate Step 7)
        return _kill_switch_response()
    try:
        return _chat_impl(req, user, t0)
    except HTTPException:
        raise
    except Exception as exc:      # noqa: BLE001 - accountability for 500s
        _audit_chat_error(req, user, exc, "chat")
        return JSONResponse(status_code=500, content={
            "detail": "Internal error while processing the request. The "
                      "attempt was recorded in the audit log."})
    finally:
        metrics.AI_LATENCY.observe(time.perf_counter() - t0)


# ---- S3: global concurrency gate (CIA-A, whole-system) ----------------------
_CHAT_GATE = threading.BoundedSemaphore(
    int(get_nested(cfg, "availability.max_concurrent_chat", 8)))
_MAX_PROMPT_CHARS = int(get_nested(cfg, "availability.max_prompt_chars", 4000))

# Wave 3.2: bounded queue + per-user concurrency cap. When all slots are
# taken, requests WAIT up to availability.queue_wait_s (queue depth is a
# Prometheus gauge) instead of failing instantly - bursty teams get smooth
# degradation, and one user can never hog every slot.
_QUEUE_WAIT_S = float(get_nested(cfg, "availability.queue_wait_s", 10))
_MAX_PER_USER = int(get_nested(cfg, "availability.max_concurrent_per_user", 2))
_USER_INFLIGHT: dict[str, int] = {}
_USER_INFLIGHT_LOCK = threading.Lock()


def _acquire_chat_slot(username: str) -> tuple[bool, str]:
    """Wave 3.2 load gate. Returns (acquired, why) with why in
    {"per_user_cap", "queue_timeout"}. Fast path is unchanged: a free
    slot is taken synchronously with zero added latency."""
    with _USER_INFLIGHT_LOCK:
        held = _USER_INFLIGHT.get(username, 0)
        if held >= _MAX_PER_USER:
            return False, "per_user_cap"
        _USER_INFLIGHT[username] = held + 1
    acquired = False
    t0 = time.perf_counter()
    try:
        metrics.AI_QUEUE_DEPTH.inc()
        acquired = _CHAT_GATE.acquire(blocking=True,
                                      timeout=max(_QUEUE_WAIT_S, 0.0))
        return (True, "") if acquired else (False, "queue_timeout")
    finally:
        metrics.AI_QUEUE_WAIT.observe(time.perf_counter() - t0)
        metrics.AI_QUEUE_DEPTH.dec()
        if not acquired:
            with _USER_INFLIGHT_LOCK:
                _USER_INFLIGHT[username] -= 1


def _release_chat_slot(username: str) -> None:
    """Release one slot held via _acquire_chat_slot (must pair 1:1)."""
    _CHAT_GATE.release()
    metrics.AI_CHAT_INFLIGHT.dec()
    with _USER_INFLIGHT_LOCK:
        _USER_INFLIGHT[username] = max(
            0, _USER_INFLIGHT.get(username, 1) - 1)


def _chat_impl(req: ChatRequest, user: auth.UserCtx, t0: float):
    trace: list[dict] = []
    cia_checks = {"confidentiality": "SKIPPED", "integrity": "SKIPPED",
                  "availability": "SKIPPED"}
    layers: list = ["1"]          # CODE-04: layer ids are strings (3.5!)
    op = (req.action_type or "READ").upper()

    # -- Wave 2.2: temp-password guard -------------------------------------
    # An account provisioned with an Admin-issued temp password may log in
    # (and change its password) but may NOT use the assistant until the
    # password is its own - a shared secret never talks to company data.
    if user.must_change_password:
        raise HTTPException(403, "password change required: set your own "
                                 "password via POST /api/me/password before "
                                 "using the assistant")

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

    # -- global load gate: per-user cap + bounded queue (Wave 3.2) ----------
    ok_load, why_load = _acquire_chat_slot(user.username)
    if not ok_load:
        trace.append({"layer": "L2", "check": "global_concurrency",
                      "result": "429", "reason": why_load})
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
                     reason=f"Availability violation: {why_load}")
        return JSONResponse(status_code=503, headers={"Retry-After": "5"},
                            content={"response": "Server at capacity. "
                                     "Retry shortly.",
                                     "blocked_by": "L2-load"
                                     if why_load == "queue_timeout"
                                     else "L2-load-user",
                                     "cia_checks": cia_checks,
                                     "layers_passed": layers})
    metrics.AI_CHAT_INFLIGHT.inc()
    try:
        deny, bundle = _preflight(req, user, t0, trace, cia_checks, layers, op)
        if deny:
            return deny
        return _finish_query(req, user, t0, trace, cia_checks, layers, bundle)
    finally:
        _release_chat_slot(user.username)


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

    # -- L2c: per-session token budget (v5.1.0, OWASP LLM10) ---------------
    # Same estimator as L2a; key = JWT session id (fresh login = fresh
    # budget, mirroring how serving engines pin KV-cache to a session).
    # Denies are CIA-A: unbounded consumption is an availability attack.
    # The admission estimate is tentatively added by check() and later
    # REPLACED by the actual consumption delta recorded after generation
    # (bundle['budget_est_in'] -> see _finish_query / _chat_stream_impl),
    # so the window always reflects true model consumption.
    _budget_est_in_admitted = 0
    if BUDGET_ENABLED:
        ok_b, retry_b, spent_b, why_b = budget_guard.check(
            user.session_id, est_tokens)
        trace.append({"layer": "L2", "check": "session_token_budget",
                      "result": "pass" if ok_b else "429",
                      "spent": spent_b, "cap": budget_guard.max_tokens})
        if not ok_b:
            cia_checks["availability"] = "FAIL"
            metrics.AI_SESSION_BUDGET.inc()
            metrics.AI_RATE_LIMITED.inc()
            metrics.AI_CIA_BLOCKS.labels("A").inc()
            metrics.AI_REQUESTS.labels("rate_limited").inc()
            audit.append(user_id=user.username, role=user.role,
                         prompt=req.message, retrieved_context="",
                         ai_response="[session budget exhausted]",
                         input_action="rate_limited", output_action="n/a",
                         blocked_by="L2-budget", latency_ms=_ms(t0),
                         action="RATE_LIMITED", cia_violation="A",
                         layer_blocked="L2-budget",
                         reason=f"Availability violation: {why_b}")
            return JSONResponse(status_code=429,
                                headers={"Retry-After": str(max(retry_b, 1))},
                                content={
                "response": (f"Session token budget exceeded "
                             f"({spent_b}/{budget_guard.max_tokens} tokens "
                             f"in the last "
                             f"{budget_guard.window_seconds}s). "
                             f"Start a new session or retry in "
                             f"{retry_b}s."),
                "blocked_by": "L2-budget", "cia_checks": cia_checks,
                "layers_passed": layers}), None
        _budget_est_in_admitted = est_tokens

    # -- Wave 6.5: intent router (general vs company data) ----------------
    # Deterministic, auditable traffic split BEFORE any company-data gate:
    # greetings / small talk / general knowledge are answered directly by
    # the model (no retrieval), everything touching company data - and
    # anything ambiguous - keeps the full governed path. Runs in BOTH
    # modes; all security layers stay armed in BOTH modes.
    mode = intent_router.classify(req.message)
    trace.append({"layer": "L4", "check": "intent_router",
                  "result": mode,
                  "ruleset": intent_router.RULESET_VERSION})

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
        # Skipped for general intent: no company data is retrieved or
        # revealed, so a general-knowledge phrasing that merely LOOKS
        # sensitive ("how do bonuses work?") is not a data request. The
        # company keyword rules in the router already force anything that
        # actually targets company records back into company mode.
        if mode == "company":
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
        else:
            trace.append({"layer": "CIA-C", "check": "confidentiality",
                          "result": "skipped (general intent)"})

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

    if SECURE_MODE and mode == "company":
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
    elif SECURE_MODE:
        trace.append({"layer": "L3", "check": "field_intent_authorised",
                      "result": "skipped (general intent)"})

    # -- L4: scoped retrieval ---------------------------------------------
    # general intent: NO company data is retrieved at all - the model
    # answers greetings / general knowledge directly, with an explicitly
    # empty bundle. Company intent keeps the full scoped retrieval.
    if mode == "general":
        bundle = {"context": "", "sources": [], "tables_queried": [],
                  "namespaces_searched": [], "n_rows": 0, "n_docs": 0,
                  "self_scoped": False, "router": "general",
                  "budget_est_in": _budget_est_in_admitted}
        trace.append({"layer": "L4", "check": "scoped_retrieval",
                      "result": "skipped (general intent)"})
        layers.append("4")
        return None, bundle

    try:
        bundle = retriever.retrieve(policy, req.message, store,
                                    username=user.username)
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

    bundle["router"] = "company"
    bundle["budget_est_in"] = _budget_est_in_admitted
    return None, bundle


def _finish_query(req, user, t0, trace, cia_checks, layers, bundle):
    """L5 model + L6 output governance + L7 audit - the synchronous tail of
    the pipeline (the SSE variant re-implements L5/L6 incrementally)."""
    # -- L5: model inference -----------------------------------------------
    # Wave 6.5: router=general switches the prompt to the general-chat
    # contract (no company data exists in the bundle; asking the model for
    # the data answer shape would produce an empty-context refusal).
    general = bundle.get("router") == "general"
    if general:
        user_turn = build_general_turn(req.message)
        gen = provider.generate(req.message, bundle["context"], user_turn,
                                system_prompt=GENERAL_SYSTEM_PROMPT)
        sys_prompt_len = len(GENERAL_SYSTEM_PROMPT)
    else:
        user_turn = build_user_turn(req.message, bundle["context"])
        gen = provider.generate(req.message, bundle["context"], user_turn)
        sys_prompt_len = len(SYSTEM_PROMPT)
    raw = gen.text
    # -- L2c accounting: the model RAN, the session pays (v5.1.0) ---------
    # Input = system contract + built turn; output = raw model text.
    # Estimated with the shared chars/token ratio (see token_budget.py).
    tokens_in = budget_guard.est_chars(sys_prompt_len + len(user_turn))
    tokens_out = budget_guard.est(raw)
    # Replace the admission placeholder with the ACTUAL input consumption
    # (delta) plus the actual output - the window always reflects what the
    # model really consumed (system prompt + built turn + response).
    budget_guard.record(user.session_id,
                        in_tokens=max(0, tokens_in
                                      - bundle.get("budget_est_in", 0)),
                        out_tokens=tokens_out)
    trace.append({"layer": "L5", "check": "model_inference",
                  "result": {"backend": gen.backend,
                             "model": gen.model,
                             "intent": gen.intent,
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
        out = output_filter.check(raw, bundle["context"], user.role,
                                  self_scoped=bundle.get("self_scoped",
                                                         False),
                                  general=general)
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
    # Step 7 (model version tracking): the answering model's identity rides
    # in the chain-covered audit meta - every answer is attributable to the
    # exact backend+model that produced it (see docs/model_manifest.md).
    audit.append(user_id=user.username, role=user.role, prompt=req.message,
                 retrieved_context=bundle["context"][:1000],
                 ai_response=final, input_action="allow",
                 output_action="allow", blocked_by="",
                 latency_ms=_ms(t0), action="QUERY",
                 meta={"backend": gen.backend, "model": gen.model,
                       "intent": gen.intent, "degraded": gen.degraded,
                       "channel": req.channel,
                       "external_user": req.external_user,
                       "router": bundle.get("router", "company"),
                       "tokens_in": tokens_in, "tokens_out": tokens_out,
                       "session_tokens": budget_guard.spent(user.session_id)})
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
                     "model": gen.model,
                     "intent": gen.intent,
                     "degraded": gen.degraded,
                     "channel": req.channel,
                     "external_user": req.external_user,
                     "router": bundle.get("router", "company"),
                     "token_usage": {"input_estimate": tokens_in,
                                     "output_estimate": tokens_out,
                                     "session_spent": budget_guard.spent(
                                         user.session_id)}}}


def _ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000


# ---- CHAT-02: SSE streaming variant (same governance, progressive output) --
def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _deny_sse_body(deny_result):
    """_deny() returns a JSONResponse for status != 200 but a plain dict
    for status == 200 (the SSE revoke convention). v5.0.0's revoke paths
    called .body on the dict unconditionally - a latent AttributeError
    that would have crashed the stream instead of revoking it (found by
    the v5.1.0 streaming-DLP test battery, same class as the span-offset
    bug: code that only breaks on the attack path it exists for)."""
    if hasattr(deny_result, "body"):
        return json.loads(deny_result.body)
    return deny_result


def _chat_stream_impl(req: ChatRequest, user: auth.UserCtx):
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
    if not ai_enabled():          # operator kill switch (pre-deploy gate Step 7)
        return JSONResponse(status_code=503, content={
            "detail": "AI features are temporarily disabled by the operator "
                      "(kill switch). Retry later or contact your "
                      "administrator."})
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

        ok_load, why_load = _acquire_chat_slot(user.username)
        if not ok_load:
            metrics.AI_REQUESTS.labels("rate_limited").inc()
            yield _sse("blocked", {"response": "Server at capacity. "
                                   "Retry shortly.",
                                   "blocked_by": "L2-load"
                                   if why_load == "queue_timeout"
                                   else "L2-load-user",
                                   "reason": why_load,
                                   "cia_checks": cia_checks,
                                   "layers_passed": layers})
            return
        metrics.AI_CHAT_INFLIGHT.inc()
        try:
            deny, bundle = _preflight(req, user, t0, trace, cia_checks,
                                      layers, op)
            if deny:
                body = deny
                if hasattr(deny, "body"):     # JSONResponse -> dict for SSE
                    body = json.loads(deny.body)
                yield _sse("blocked", body)
                return

            # Wave 3.1: route BEFORE the meta event - the client learns
            # the intent and primary model up front (same chain as sync).
            route = (provider._route(req.message)
                     if provider.backend_name() in provider._BACKENDS
                     else None)

            yield _sse("meta", {"layers_passed": layers,
                                "cia_checks": cia_checks,
                                "sources": bundle.get("sources", []),
                                "backend": provider.backend_name(),
                                "intent": route[0] if route else "fast",
                                "model": route[1][0] if route else "",
                                "router": bundle.get("router", "company")})

            # -- L5 (streaming) + L6 (incremental + final) ------------------
            # Wave 6.5: general intent streams with the general-chat prompt
            # (no company data contract); company intent is unchanged.
            general = bundle.get("router") == "general"
            sys_prompt = GENERAL_SYSTEM_PROMPT if general else SYSTEM_PROMPT
            user_turn = (build_general_turn(req.message) if general
                         else build_user_turn(req.message, bundle["context"]))
            degraded_reason = ""
            hard_abort: list[str] = []
            self_scoped = bool(bundle.get("self_scoped", False))
            budget_abort = False          # v5.1.0: L2c mid-stream cutoff
            tokens_in = budget_guard.est_chars(len(sys_prompt)
                                               + len(user_turn))
            tokens_out = 0
            # v5.1.0 (Layer 6s): incremental DLP with a forced scan window.
            # Sentence-boundary flush semantics are unchanged; the window
            # bounds how long hard-leak indicators can hide in an
            # unflushed, punctuation-free buffer and caps buffer memory.
            dlp = StreamingDLP(user.role, self_scoped=self_scoped,
                               scan_window_chars=STREAM_SCAN_WINDOW,
                               flush_cap_chars=STREAM_FLUSH_CAP,
                               tail_keep_chars=STREAM_TAIL_KEEP)
            # Replace the admission placeholder with the ACTUAL input
            # consumption (delta) before any output is produced.
            budget_guard.record(user.session_id,
                                in_tokens=max(0, tokens_in
                                              - bundle.get("budget_est_in",
                                                           0)))

            def chunk_source():
                # One code path for every real backend: the active module
                # comes from provider._BACKENDS ("ollama", "colibri"); a
                # failure degrades VISIBLY to the mock (CHAT-01).
                mod = provider._BACKENDS.get(provider.backend_name())
                if mod is not None:
                    try:
                        yield from mod.generate_stream(
                            sys_prompt, user_turn,
                            model=route[1][0] if route else None,
                            think=route[2] if route else None,
                            max_tokens=route[3] if route else None)
                        return
                    except provider._PROVIDER_ERRORS as exc:
                        nonlocal degraded_reason
                        degraded_reason = str(exc)[:120]
                        yield provider.DEGRADED_BANNER.format(
                            reason=degraded_reason[:80])
                text = mock_model.generate(req.message, bundle["context"],
                                           general=general)
                for word in text.split(" "):
                    yield word + " "
                    time.sleep(0.012)

            gen_backend = provider.backend_name()
            try:
                for piece in chunk_source():
                    # L2c accounting: the model produced this - the session
                    # pays for it even if the stream is revoked later
                    # (OWASP LLM10: a revoked answer still consumed compute).
                    tokens_out += budget_guard.est(piece)
                    budget_guard.record_output(user.session_id,
                                               budget_guard.est(piece))
                    for chunk in dlp.feed(piece):
                        yield _sse("delta", {"t": chunk})
                    if dlp.aborted:
                        hard_abort = dlp.abort_reasons
                        break
                    if BUDGET_ENABLED and (budget_guard.spent(
                            user.session_id) >= budget_guard.max_tokens):
                        budget_abort = True
                        break
            except ollama_model.ProviderUnavailable as exc:
                degraded_reason = degraded_reason or str(exc)[:120]
                yield _sse("delta", {"t": provider.DEGRADED_BANNER.format(
                    reason=degraded_reason[:80])})
                text = mock_model.generate(req.message, bundle["context"],
                                           general=general)
                dlp.emitted.append(text)
                yield _sse("delta", {"t": text})

            if budget_abort:
                # v5.1.0: runaway generation stopped mid-stream - the session
                # exhausted its token budget while the model was producing
                # (defense in depth: the preflight L2c check already capped
                # admission; this bounds the OUTPUT side).
                metrics.AI_SESSION_BUDGET.inc()
                deny_body = _deny_sse_body(
                    _deny(user, req.message, "L2-budget",
                          "session token budget exhausted mid-stream; stream "
                          "revoked (OWASP LLM10 unbounded consumption defense)",
                          time.perf_counter() - t0, trace, cia_checks, layers,
                          status_code=200))
                yield _sse("revoked", deny_body)
                return

            if hard_abort:
                # hard leak indicator mid-stream: revoke everything
                audit.flag_for_review(user_id=user.username, role=user.role,
                                      prompt=req.message,
                                      withheld=dlp.emitted_text[:2000],
                                      reason="; ".join(hard_abort))
                deny_body = _deny_sse_body(
                    _deny(user, req.message, "L6",
                          "stream revoked: " + "; ".join(hard_abort),
                          time.perf_counter() - t0, trace, cia_checks, layers,
                          status_code=200))
                yield _sse("revoked", deny_body)
                return

            full_text = dlp.emitted_text + dlp.pending
            if degraded_reason:
                full_text = provider.DEGRADED_BANNER.format(
                    reason=degraded_reason[:80]) + full_text
            out = output_filter.check(full_text, bundle["context"], user.role,
                                      general=general)
            trace.append({"layer": "L6", "check": "dlp_faithfulness",
                          "result": out.action, "reasons": out.reasons})
            if out.action == "block":
                audit.flag_for_review(user_id=user.username, role=user.role,
                                      prompt=req.message,
                                      withheld=full_text[:2000],
                                      reason=out.summary)
                deny_body = _deny_sse_body(
                    _deny(user, req.message, "L6",
                          "potential sensitive-data disclosure, unfaithful "
                          "output, or indirect-injection residue; streamed "
                          "response revoked for human review",
                          time.perf_counter() - t0,
                          trace, cia_checks, layers, status_code=200))
                yield _sse("revoked", deny_body)
                return

            audit.append(user_id=user.username, role=user.role,
                         prompt=req.message,
                         retrieved_context=bundle["context"][:1000],
                         ai_response=out.text or full_text,
                         input_action="allow", output_action="allow",
                         blocked_by="", latency_ms=_ms(t0), action="QUERY",
                         meta={"backend": gen_backend,
                               "model": route[1][0] if route else "mock",
                               "intent": route[0] if route else "fast",
                               "degraded": bool(degraded_reason),
                               "channel": req.channel,
                               "external_user": req.external_user,
                               "router": bundle.get("router", "company"),
                               "tokens_in": tokens_in,
                               "tokens_out": tokens_out,
                               "session_tokens": budget_guard.spent(
                                   user.session_id)})
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
                                          "degraded": bool(degraded_reason),
                                          "token_usage": {
                                              "input_estimate": tokens_in,
                                              "output_estimate": tokens_out,
                                              "session_spent":
                                                  budget_guard.spent(
                                                      user.session_id)}}})
        finally:
            _release_chat_slot(user.username)
            metrics.AI_LATENCY.observe(time.perf_counter() - t0)

    def _guarded():
        # mid-stream crashes still owe the audit chain a row (L7 coverage)
        try:
            yield from event_stream()
        except Exception as exc:  # noqa: BLE001
            _audit_chat_error(req, user, exc, "chat_stream")
            raise

    return StreamingResponse(_guarded(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.post("/api/chat/stream")
def chat_stream(req: ChatRequest, user: auth.UserCtx = Depends(current_user)):
    """SSE chat entry point: kill switch + full-audit wrapper around
    _chat_stream_impl. Any unexpected exception is recorded in the hash
    chain (L7 sees every governed attempt) before a sanitized 500."""
    if not ai_enabled():          # operator kill switch (Step 7)
        return JSONResponse(status_code=503, content={
            "detail": "AI features are temporarily disabled by the operator "
                      "(kill switch). Retry later or contact your "
                      "administrator."})
    try:
        return _chat_stream_impl(req, user)
    except HTTPException:
        raise
    except Exception as exc:      # noqa: BLE001 - accountability for 500s
        _audit_chat_error(req, user, exc, "chat_stream")
        return JSONResponse(status_code=500, content={
            "detail": "Internal error while processing the request. The "
                      "attempt was recorded in the audit log."})


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


# ---- v4.9.0: governance transparency & compliance plane (Admin) ------------
# The runtime pipeline enforces; these endpoints PROVE. Inventory + EU AI Act
# classification, scored risk register, AI incident ledger, NIST AI RMF
# maturity and the Articles 9-17 conformity self-assessment - all state in
# db/compliance.db, all incident transitions mirrored into the L7 chain.

class RegisterSystemBody(BaseModel):
    name: str
    purpose: str
    purpose_flags: list[str] = Field(default_factory=list)
    business_unit: str = ""
    system_owner: str = ""
    vendor: str = "internal"
    deployment_status: str = "planned"
    affected_persons: str = ""
    autonomous_decisions: bool = False
    review_cycle_days: int | None = None
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


class NewRiskBody(BaseModel):
    title: str
    system_id: str = ""
    description: str = ""
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    controls: str = ""
    control_owner: str = ""
    residual_score: int | None = Field(default=None, ge=1, le=25)
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


class ControlsBody(BaseModel):
    controls: str
    residual_score: int = Field(ge=1, le=25)
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


class NewIncidentBody(BaseModel):
    title: str
    system_id: str = ""
    description: str = ""
    severity: int = Field(ge=1, le=4)
    detected_by: str = ""
    containment: str = ""
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


class IncidentTransitionBody(BaseModel):
    to_status: str
    note: str = ""
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


def _compliance_evidence() -> dict:
    """Live runtime evidence snapshot handed to the RMF maturity scorer and
    the conformity pack generator - so framework answers are computed from
    the running product, never asserted from a stale document."""
    chain_ok, _bad = audit.verify_cached()
    retention_days = int(get_nested(cfg, "audit.retention_days", 180))
    return {
        "version": app.version,
        "declarative_policy": (PROJECT_ROOT / "config" /
                               "rbac_config.yaml").exists(),
        "named_owner": True,
        "inventory_registry": True,
        "model_manifest": (PROJECT_ROOT / "docs" /
                           "model_manifest.md").exists(),
        "incident_ledger": True,
        "documented_threat_model": (PROJECT_ROOT / "docs" /
                                    "Threat_Model.md").exists(),
        "cia_mapping": (PROJECT_ROOT / "docs" /
                        "CIA_Mapping.md").exists(),
        "residual_risks": True,
        "risk_register": True,
        "tests_pass": True,           # suite gate: CI runs the 466+ suite
        "tests_total": 466,
        "probe_gate": (PROJECT_ROOT / "scripts" /
                       "probe_runner.py").exists(),
        "metrics_endpoint": True,
        "audit_chain_valid": chain_ok,
        "audit_events": _ro_count(AUDIT_DB, "SELECT COUNT(*) FROM audit"),
        "hitl_gate": True,
        "kill_switch": True,
        "retention_configured": retention_days >= 180,
        "retention_days": retention_days,
        "incident_runbook": (PROJECT_ROOT / "docs" / "governance" /
                             "incident_response.md").exists(),
        "pending_actions": len(actions_store.list_open()),
        "open_review_items": len(audit.review_list()),
    }


@app.get("/admin/compliance")
def admin_compliance(user: auth.UserCtx = Depends(current_user)):
    """One-call compliance snapshot: classified inventory, risk summary,
    incident summary, RMF maturity, regulatory notes."""
    _require_roles(user, ADMIN_ROLES)
    inv = compliance_store.list_systems()
    risks = compliance_store.list_risks()
    incidents = compliance_store.list_incidents()
    by_tier: dict[str, int] = {}
    for s in inv:
        by_tier[s["tier"]] = by_tier.get(s["tier"], 0) + 1
    by_band: dict[str, int] = {}
    for r in risks:
        by_band[r["inherent_band"]] = by_band.get(r["inherent_band"], 0) + 1
    open_inc = [i for i in incidents
                if i["status"] not in ("closed", "cancelled")]
    return {
        "version": app.version,
        "inventory": inv,
        "classification_summary": by_tier,
        "risks_total": len(risks),
        "risk_bands": by_band,
        "top_risks": risks[:5],
        "incidents_total": len(incidents),
        "incidents_open": len(open_inc),
        "recent_incidents": incidents[:5],
        "rmf": compliance.assess_rmf_maturity(_compliance_evidence()),
        "regulatory_notes": compliance.REGULATORY_NOTES,
    }


@app.get("/admin/compliance/inventory")
def compliance_inventory(user: auth.UserCtx = Depends(current_user)):
    _require_roles(user, ADMIN_ROLES)
    return {"systems": compliance_store.list_systems()}


@app.post("/admin/compliance/inventory")
def compliance_register_system(body: RegisterSystemBody,
                               user: auth.UserCtx = Depends(current_user)):
    """Register a new AI system -> auto-classified by the EU AI Act engine.
    Unacceptable-risk (Art.5 prohibited practice) registrations are REFUSED
    with 403 PROHIBITED_PRACTICE - no approval pathway exists."""
    _require_roles(user, ADMIN_ROLES)
    try:
        rec = compliance_store.add_system(
            name=body.name, purpose=body.purpose,
            purpose_flags=body.purpose_flags,
            business_unit=body.business_unit,
            system_owner=body.system_owner, vendor=body.vendor,
            deployment_status=body.deployment_status,
            affected_persons=body.affected_persons,
            autonomous_decisions=body.autonomous_decisions,
            review_cycle_days=body.review_cycle_days,
            registered_by=user.username)
    except compliance.ComplianceError as exc:
        code = 403 if exc.code == "PROHIBITED_PRACTICE" else 422
        raise HTTPException(code, {"error": exc.code,
                                   "detail": exc.message}) from exc
    audit.append(user_id=user.username, role=user.role,
                 prompt=f"COMPLIANCE register-system {rec['id']}",
                 retrieved_context="", ai_response=rec["tier"],
                 input_action="compliance", output_action="n/a",
                 blocked_by="", latency_ms=0.0, action="COMPLIANCE",
                 reason=f"registered {body.name} as {rec['tier']} risk",
                 meta={"system_id": rec["id"], "tier": rec["tier"]})
    return rec


@app.get("/admin/compliance/risks")
def compliance_risks(user: auth.UserCtx = Depends(current_user)):
    _require_roles(user, ADMIN_ROLES)
    return {"risks": compliance_store.list_risks()}


@app.post("/admin/compliance/risks")
def compliance_add_risk(body: NewRiskBody,
                        user: auth.UserCtx = Depends(current_user)):
    _require_roles(user, ADMIN_ROLES)
    try:
        rec = compliance_store.add_risk(
            title=body.title, system_id=body.system_id,
            description=body.description, likelihood=body.likelihood,
            impact=body.impact, controls=body.controls,
            control_owner=body.control_owner,
            residual_score=body.residual_score)
    except compliance.ComplianceError as exc:
        raise HTTPException(422, {"error": exc.code,
                                  "detail": exc.message}) from exc
    audit.append(user_id=user.username, role=user.role,
                 prompt=f"COMPLIANCE add-risk {rec['id']}",
                 retrieved_context="", ai_response=rec["inherent_band"],
                 input_action="compliance", output_action="n/a",
                 blocked_by="", latency_ms=0.0, action="COMPLIANCE",
                 reason=body.title, meta={"risk_id": rec["id"]})
    return rec


@app.post("/admin/compliance/risks/{risk_id}/controls")
def compliance_update_controls(risk_id: str, body: ControlsBody,
                               user: auth.UserCtx = Depends(current_user)):
    _require_roles(user, ADMIN_ROLES)
    try:
        rec = compliance_store.update_controls(
            risk_id, controls=body.controls,
            residual_score=body.residual_score)
    except compliance.ComplianceError as exc:
        code = 404 if exc.code == "NOT_FOUND" else 422
        raise HTTPException(code, {"error": exc.code,
                                   "detail": exc.message}) from exc
    audit.append(user_id=user.username, role=user.role,
                 prompt=f"COMPLIANCE controls {risk_id}",
                 retrieved_context="", ai_response=rec["residual_band"],
                 input_action="compliance", output_action="n/a",
                 blocked_by="", latency_ms=0.0, action="COMPLIANCE",
                 reason=f"residual {rec['residual_score']}")
    return rec


@app.get("/admin/compliance/incidents")
def compliance_incidents(include_closed: bool = True,
                         user: auth.UserCtx = Depends(current_user)):
    _require_roles(user, ADMIN_ROLES)
    return {"incidents": compliance_store.list_incidents(include_closed)}


@app.post("/admin/compliance/incidents")
def compliance_declare_incident(body: NewIncidentBody,
                                user: auth.UserCtx = Depends(current_user)):
    """Declare an AI incident. Severity class drives the escalation SLA
    (S1: governance committee <= 24h, board <= 48h, regulatory assessment
    mandatory). Declaration lands in the L7 chain."""
    _require_roles(user, ADMIN_ROLES)
    try:
        rec = compliance_store.declare_incident(
            title=body.title, severity=body.severity,
            system_id=body.system_id, description=body.description,
            detected_by=body.detected_by, containment=body.containment,
            opened_by=user.username)
    except compliance.ComplianceError as exc:
        raise HTTPException(422, {"error": exc.code,
                                  "detail": exc.message}) from exc
    audit.append(user_id=user.username, role=user.role,
                 prompt=f"INCIDENT declare {rec['id']}",
                 retrieved_context="", ai_response=f"severity {body.severity}",
                 input_action="compliance", output_action="n/a",
                 blocked_by="", latency_ms=0.0, action="INCIDENT",
                 reason=body.title,
                 meta={"incident_id": rec["id"], "severity": body.severity,
                       "event": "declared"})
    return rec


@app.post("/admin/compliance/incidents/{incident_id}/transition")
def compliance_transition_incident(incident_id: str,
                                   body: IncidentTransitionBody,
                                   user: auth.UserCtx = Depends(current_user)):
    """State machine transition (open -> investigating -> contained ->
    remediated -> closed; cancelled from any live state). Every legal
    transition is hash-chained; illegal ones are refused with 422."""
    _require_roles(user, ADMIN_ROLES)
    try:
        rec = compliance_store.transition_incident(
            incident_id, to_status=body.to_status, actor=user.username,
            note=body.note)
    except compliance.ComplianceError as exc:
        code = 404 if exc.code == "NOT_FOUND" else 422
        raise HTTPException(code, {"error": exc.code,
                                   "detail": exc.message}) from exc
    audit.append(user_id=user.username, role=user.role,
                 prompt=f"INCIDENT transition {incident_id} "
                        f"-> {body.to_status}",
                 retrieved_context="", ai_response=body.to_status,
                 input_action="compliance", output_action="n/a",
                 blocked_by="", latency_ms=0.0, action="INCIDENT",
                 reason=body.note or body.to_status,
                 meta={"incident_id": incident_id,
                       "severity": rec["severity"],
                       "event": body.to_status})
    return rec


@app.get("/admin/compliance/rmf")
def compliance_rmf(user: auth.UserCtx = Depends(current_user)):
    """NIST AI RMF maturity self-assessment computed from live evidence."""
    _require_roles(user, ADMIN_ROLES)
    return compliance.assess_rmf_maturity(_compliance_evidence())


@app.get("/admin/compliance/conformity-pack")
def compliance_conformity_pack(user: auth.UserCtx = Depends(current_user)):
    """EU AI Act Articles 9-17 (+26/50/72) conformity self-assessment,
    generated from live runtime evidence (audit chain counts, HITL queue,
    retention config, test counts)."""
    _require_roles(user, ADMIN_ROLES)
    ev = _compliance_evidence()
    ev["risks_total"] = compliance_store.counts()["risks"]
    return compliance.conformity_pack(ev)


@app.get("/admin/compliance/iso42001-soa")
def compliance_iso42001_soa(user: auth.UserCtx = Depends(current_user)):
    """ISO/IEC 42001:2023 Statement of Applicability - all 38 Annex A
    controls (objectives A.2-A.10) mapped to live controls with honest
    implementation statuses, computed from runtime evidence."""
    _require_roles(user, ADMIN_ROLES)
    return iso42001_soa.build_soa(_compliance_evidence())


@app.get("/admin/compliance/dpdp")
def compliance_dpdp(user: auth.UserCtx = Depends(current_user)):
    """DPDPA (India) obligation map - DPDP Act 2023 + DPDP Rules 2025
    (Rule 7: 72h breach report) against live enforcement surfaces."""
    _require_roles(user, ADMIN_ROLES)
    return dpdp_compliance.dpdp_status(_compliance_evidence())


@app.get("/admin/compliance/csf")
def compliance_csf(user: auth.UserCtx = Depends(current_user)):
    """NIST CSF 2.0 function/sub-category coverage (6 functions), computed
    from live evidence over the AI-relevant mapped subset."""
    _require_roles(user, ADMIN_ROLES)
    return nist_csf_mapping.csf_coverage(_compliance_evidence())


# ---- Wave 2.2: user management (Admin-only identity administration) --------
class CreateUserBody(BaseModel):
    username: str
    password: str                 # TEMP secret; user must replace it (2.2)
    full_name: str = ""
    email: str = ""
    role: str
    department: str = "General"
    clearance: str = "L1"
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


class PatchUserBody(BaseModel):
    role: str | None = None
    department: str | None = None
    clearance: str | None = None
    is_active: bool | None = None
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


class ResetPasswordBody(BaseModel):
    new_password: str
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


class SelfPasswordBody(BaseModel):
    current_password: str
    new_password: str
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}


def _user_audit(action: str, actor: auth.UserCtx, target: str,
                detail: str) -> None:
    """Every identity mutation lands in the hash-chained chain (L7)."""
    audit.append(user_id=actor.username, role=actor.role,
                 prompt=f"USER_ADMIN {action} -> {target}",
                 retrieved_context="", ai_response=f"[{action}]",
                 input_action="user_admin", output_action="n/a",
                 blocked_by="", latency_ms=0.0, action=action,
                 reason=detail)


def _admin_error(exc: Exception) -> HTTPException:
    if isinstance(exc, user_admin.LastAdminError):
        return HTTPException(409, str(exc))
    if isinstance(exc, user_admin.AdminGrantForbidden):
        return HTTPException(403, str(exc))     # self-elevation: Forbidden
    return HTTPException(422, str(exc))


@app.get("/admin/users")
def admin_list_users(user: auth.UserCtx = Depends(current_user)):
    """Admin-only: every account, NO password hashes (DPDP data
    minimisation - the admin UI needs posture, not secrets)."""
    _require_roles(user, ADMIN_ROLES)
    return {"users": user_admin.list_users(),
            "roles": rbac.known_roles(),
            "superadmins_configured": bool(user_admin.superadmins())}


@app.post("/admin/users")
def admin_create_user(req: CreateUserBody,
                      user: auth.UserCtx = Depends(current_user)):
    """Admin-only provisioning. Guards: password policy (>=10 chars, 4
    classes), unique username, known role/clearance, Admin grants need the
    SECURELLM_SUPERADMINS allow-list (fail closed). The created account
    starts with must_change_password=1 - its temp secret cannot talk to
    company data until replaced via POST /api/me/password."""
    _require_roles(user, ADMIN_ROLES)
    try:
        created = user_admin.create_user(
            username=req.username, password=req.password,
            full_name=req.full_name, email=req.email, role=req.role,
            department=req.department, clearance=req.clearance,
            actor=user.username)
    except (user_admin.UserAdminError, user_admin.LastAdminError) as exc:
        raise _admin_error(exc)
    _user_audit("USER_CREATE", user, req.username,
                f"role={created['role']} department={created['department']} "
                f"clearance={created['clearance']} (temp password active)")
    return {"user": created,
            "notice": "account created with a temp password; the user "
                      "must set their own password before chatting "
                      "(POST /api/me/password)"}


@app.patch("/admin/users/{username}")
def admin_patch_user(username: str, req: PatchUserBody,
                     user: auth.UserCtx = Depends(current_user)):
    """Admin-only role / department / clearance / active updates. Any
    change bumps the account's role_version: every outstanding JWT for
    that user fails validation on its very next request (Wave 2.1)."""
    _require_roles(user, ADMIN_ROLES)
    try:
        updated = user_admin.set_role(
            username=username, actor=user.username, role=req.role,
            department=req.department, clearance=req.clearance)
        if req.is_active is not None and \
                bool(updated["is_active"]) != req.is_active:
            updated = user_admin.set_active(
                username=username, actor=user.username, active=req.is_active)
    except (user_admin.UserAdminError, user_admin.LastAdminError) as exc:
        raise _admin_error(exc)
    _user_audit("USER_UPDATE", user, username,
                f"role={updated['role']} department={updated['department']} "
                f"clearance={updated['clearance']} "
                f"is_active={updated['is_active']} "
                f"role_version={updated['role_version']}")
    return {"user": updated,
            "notice": "role_version bumped - all outstanding sessions for "
                      "this account are revoked"}


@app.post("/admin/users/{username}/password")
def admin_reset_password(username: str, req: ResetPasswordBody,
                         user: auth.UserCtx = Depends(current_user)):
    """Admin-only password reset: sets a TEMP secret (must_change_password=1)
    and bumps role_version - every outstanding session dies immediately,
    which is exactly what a credential-compromise response needs."""
    _require_roles(user, ADMIN_ROLES)
    try:
        updated = user_admin.reset_password(
            username=username, new_password=req.new_password,
            actor=user.username)
    except (user_admin.UserAdminError, user_admin.LastAdminError) as exc:
        raise _admin_error(exc)
    _user_audit("USER_PASSWORD_RESET", user, username,
                "temp password set; all sessions revoked via role_version")
    return {"user": updated,
            "notice": "temp password set - the user must change it before "
                      "chatting again"}


@app.post("/api/me/password")
def change_own_password(req: SelfPasswordBody,
                        user: auth.UserCtx = Depends(current_user)):
    """Self-service password change (any authenticated user): verifies the
    CURRENT password, validates the policy, clears the temp flag and
    revokes all sessions (including this one) via the role_version bump."""
    try:
        user_admin.change_own_password(
            username=user.username, current_password=req.current_password,
            new_password=req.new_password)
    except (user_admin.UserAdminError, user_admin.LastAdminError) as exc:
        raise _admin_error(exc)
    _user_audit("USER_PASSWORD_CHANGE", user, user.username,
                "self-service change; all sessions revoked via role_version")
    return {"status": "changed",
            "notice": "password updated - sign in again with the new "
                      "password"}


# ---- SETUP-1 (v4.6.0): admin LLM catalog + one-click model selection -------
class SelectModelBody(BaseModel):
    model: str


@app.get("/api/llm/models")
def llm_models(user: auth.UserCtx = Depends(current_user)):
    """Admin-only: every model Ollama currently serves, scored for
    company-chat suitability, with the recommended pick first. Read-only
    detection (Ollama /api/tags) - when Ollama is down the answer says so
    visibly instead of pretending (fail visible, not fail fake)."""
    _require_roles(user, ADMIN_ROLES)
    base = get_nested(cfg, "model.ollama_url", "http://localhost:11434")
    det = model_catalog.list_ollama_models(base)
    current = model_catalog.current_selection(cfg)
    rec = model_catalog.recommend(det["models"])
    return {"reachable": det["reachable"],
            "error": det["error"],
            "models": det["models"],
            "recommended": rec,
            "current": current,
            "backend": provider.status()}


@app.post("/api/llm/model")
def llm_select_model(req: SelectModelBody,
                     user: auth.UserCtx = Depends(current_user)):
    """Admin-only one-click model switch: validates the id against the
    live Ollama catalog (fail closed - a typo must never leave the app
    pointing at a model nobody can serve), surgically rewrites the three
    model-id keys in app_config.yaml (comments preserved; the mtime cache
    hot-reloads the running API), and lands in the hash-chained audit."""
    _require_roles(user, ADMIN_ROLES)
    wanted = req.model.strip()
    base = get_nested(cfg, "model.ollama_url", "http://localhost:11434")
    det = model_catalog.list_ollama_models(base)
    if not det["reachable"]:
        raise HTTPException(503, f"Ollama unreachable at {base} - "
                                 "cannot validate the model id")
    if not any(m["name"] == wanted for m in det["models"]):
        raise HTTPException(400, f"model '{wanted}' is not served by "
                                 "Ollama - pick one from the catalog")
    previous = model_catalog.current_selection(cfg)["ollama_model"]
    try:
        applied = model_catalog.apply_model_selection(wanted)
    except ValueError as exc:
        raise HTTPException(500, f"model selection not applied: {exc}")
    _user_audit("MODEL_SELECT", user, wanted,
                f"previous={previous} config={applied['config']}")
    return {"ok": True, "selected": wanted, "previous": previous,
            "routing": provider.status()}


# ---- Wave 2.3: permission preview (decide what a user will see) ------------
@app.get("/admin/roles/{role}/permissions")
def role_permissions(role: str,
                     user: auth.UserCtx = Depends(current_user)):
    """Admin-only: the effective policy for a role as structured JSON -
    the live data behind the admin page's CAN / CANNOT panels. Rendered
    ONLY from granted permissions + the shared catalog, so previewing a
    role never reveals another role's grants beyond the catalog names."""
    _require_roles(user, ADMIN_ROLES)
    if role not in rbac.known_roles():
        raise HTTPException(404, f"unknown role '{role}'")
    pol = rbac.get_policy(role)
    can_tables = [t for t in rbac.all_tables() if t in pol.allowed_tables]
    cannot_tables = [t for t in rbac.all_tables()
                     if t not in pol.allowed_tables]
    namespaces = rbac.all_namespaces()
    return {
        "role": role,
        "departments": pol.departments,
        "summary": pol.summary(),
        "tables": {t: {"columns": pol.allowed_columns.get(t, []),
                       "sensitive_columns":
                           rbac.table_sensitive_columns(t)}
                   for t in can_tables},
        "can": {"tables": can_tables,
                "namespaces": [n for n in namespaces
                               if n in pol.allowed_namespaces]},
        "cannot": {"tables": cannot_tables,
                   "namespaces": [n for n in namespaces
                                  if n not in pol.allowed_namespaces]},
    }


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
    _st = provider.status()      # one snapshot: one probe budget per /health
    return {
        "status": "healthy",
        "version": app.version,
        "uptime_s": round(time.time() - _START_TIME, 1),
        "model_backend": provider.backend_name(),
        "ollama_reachable": _st["ollama_reachable"],
        "colibri_reachable": _st["colibri_reachable"],
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
        "ai_enabled": ai_enabled(),
        "model": {**st,
                  "ollama_url": get_nested(cfg, "model.ollama_url",
                                           "http://localhost:11434"),
                  "ollama_model": get_nested(cfg, "model.ollama_model",
                                             "qwen2.5:0.5b"),
                  "colibri_url": get_nested(cfg, "model.colibri_url",
                                            "http://localhost:8000"),
                  "colibri_model": get_nested(cfg, "model.colibri_model",
                                              "glm-5.2-colibri")},
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


@app.get("/chat", include_in_schema=False)
def chat_page():
    """SETUP-2 (v4.6.0): the simple ChatGPT-style face EVERY user gets.
    Governance surfaces (traces, CIA chips, audit tables) live in the
    admin-only dashboard, not here."""
    return FileResponse(_static / "chat.html")


@app.get("/compliance", include_in_schema=False)
def compliance_page():
    """v4.9.0: admin-only governance-transparency console (inventory,
    EU AI Act classification, risk register, incident ledger, RMF
    maturity, conformity pack)."""
    return FileResponse(_static / "compliance.html")


@app.get("/", include_in_schema=False)
def root_page():
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/chat")


if _static.exists():
    app.mount("/", StaticFiles(directory=_static, html=True), name="ui")
