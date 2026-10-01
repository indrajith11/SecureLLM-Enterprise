"""Operational availability metrics - the CIA "Availability" leg in code.

Exposes a /metrics endpoint in Prometheus text format so any Prometheus /
Grafana / Alertmanager stack can scrape the AI system's live posture:

  ai_requests_total{decision}        every /chat outcome (allow | blocked)
  ai_blocked_prompts_total{layer}    which governance layer stopped it
  ai_output_redactions_total         Layer 6 withheld responses
  ai_rate_limited_total              Layer 2 rate limiter rejections
  ai_action_requests_total{status}   HITL pending-action lifecycle (L3.5)
  ai_latency_seconds                 end-to-end /chat latency histogram
  http_requests_total{method,path,status}  generic HTTP traffic

Why this matters for governance: NIST AI RMF "Measure" is not only red-team
scores - it is continuous monitoring in production (ISO 27001 A.8.16,
SOC 2 CC7.2). A spike in ai_blocked_prompts_total is an incident signal;
ai_output_redactions_total trending up is a data-leak early-warning.

prometheus-client is the only dependency; the endpoint is wired in
src/api/main.py via prometheus_client.make_asgi_app(registry=REG).

REG is a dedicated CollectorRegistry: scripts/probe_runner.py reloads the
src.* modules to switch secure/baseline mode, and a fresh registry per
module import keeps that honest re-measurement loop crash-free.
"""
import time

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

REG = CollectorRegistry(auto_describe=True)

_START = time.time()

AI_REQUESTS = Counter(
    "ai_requests_total",
    "Total /chat requests processed, by final decision",
    ["decision"], registry=REG)

AI_BLOCKED = Counter(
    "ai_blocked_prompts_total",
    "Prompts or outputs blocked, by governance layer (L2/L3.5/L6)",
    ["layer"], registry=REG)

AI_REDACTIONS = Counter(
    "ai_output_redactions_total",
    "Model outputs withheld/redacted by Layer 6 output governance",
    registry=REG)

AI_RATE_LIMITED = Counter(
    "ai_rate_limited_total",
    "Requests rejected by the Layer 2 token-aware rate limiter",
    registry=REG)

AI_ACTIONS = Counter(
    "ai_action_requests_total",
    "High-risk action requests seen by the HITL agency gate, by status",
    ["status"], registry=REG)

AI_CIA_BLOCKS = Counter(
    "ai_cia_blocks_total",
    "Requests refused by per-user CIA triad enforcement, by pillar (C/I/A)",
    ["pillar"], registry=REG)

AI_INPUT_RULES = Counter(
    "ai_input_rule_hits_total",
    "Layer 2b firewall rule-family hits, by category (WAF-style attribution)",
    ["category"], registry=REG)

AI_DENIALS = Counter(
    "ai_denials_total",
    "Official policy denials rendered by the Denial Engine, by reason code "
    "(AUTHZ_TABLE/AUTHZ_FIELD/AUTHZ_ROW/CIA_C_DOC/DLP_OUTPUT/INPUT_BLOCKED)",
    ["code"], registry=REG)

AI_LOGINS = Counter(
    "ai_auth_events_total",
    "Authentication events, by outcome (login | denied | locked | logout)",
    ["outcome"], registry=REG)

AI_LATENCY = Histogram(
    "ai_latency_seconds",
    "End-to-end /chat latency in seconds",
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
    registry=REG)

HTTP_REQUESTS = Counter(
    "http_requests_total",
    "HTTP requests handled, by method/path-template/status",
    ["method", "path", "status"], registry=REG)

UPTIME = Gauge(
    "process_uptime_seconds",
    "Seconds since this process started serving traffic",
    registry=REG)


def observe_uptime():
    UPTIME.set(time.time() - _START)


def sample(name: str, labels: dict | None = None) -> float | None:
    """Test/debug helper: one labelled sample value (None if absent)."""
    return REG.get_sample_value(name, labels or {})


def snapshot(names: list[str]) -> dict:
    """Test/debug helper: current values for the given metric names."""
    out = {}
    for name in names:
        for metric in REG.collect():
            if metric.name == name:
                for s in metric.samples:
                    out.setdefault(name, {})[
                        tuple(sorted(s.labels.items()))] = s.value
    return out


def normalise_path(path: str) -> str:
    """Collapse ids in paths so the `path` label has bounded cardinality
    (/api/action/confirm/17 -> /api/action/confirm/{id})."""
    if not path.startswith("/"):
        return path
    parts = []
    for seg in path.strip("/").split("/"):
        parts.append("{id}" if seg.isdigit() else seg)
    return "/" + "/".join(parts)
