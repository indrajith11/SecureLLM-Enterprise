"""Wave 6.5 - end-to-end intent routing through the governed API.

Pinned guarantees:
  - a general message (greeting / general knowledge) is answered WITHOUT
    company retrieval: empty sources, 'scoped_retrieval skipped' in the
    trace, and meta.router == 'general';
  - company-data questions keep the FULL governed path (retrieval + RBAC
    + sources + meta.router == 'company');
  - general intent skips the CIA-C keyword pre-filter and the L3+ field-
    intent denial (a general phrasing like 'how do bonuses work?' is not
    a data request) while L2b/L3.5 stay armed;
  - general-mode L6 keeps HARD leakage rules armed but does not redact
    legitimate general figures against an empty context;
  - the routing decision lands in the L7 audit meta.
"""
import pytest

from src.governance import output_filter
from src.router import intent as intent_router

from tests.conftest import client as _client  # noqa: F401  (fixture import)
from tests.conftest import login


def test_router_classifies_before_retrieval(client, alice):
    r = client.post("/api/chat", headers=alice,
                    json={"message": "hi", "channel": "web"})
    assert r.status_code == 200, r.text
    body = r.json()
    meta = body["meta"]
    assert meta["router"] == "general"
    assert body["sources"] == []
    trace = {t["check"]: t["result"] for t in meta["trace"]}
    assert trace["intent_router"] == "general"
    assert trace["scoped_retrieval"] == "skipped (general intent)"
    assert trace["confidentiality"] == "skipped (general intent)"
    # the mock general reply is a friendly answer, NOT the data denial
    assert "Hello" in body["response"]
    assert "Access Denied" not in body["response"]


def test_company_question_keeps_full_path(client, alice):
    r = client.post("/api/chat", headers=alice,
                    json={"message": "What is the remote work policy?",
                          "channel": "web"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["meta"]["router"] == "company"
    trace = {t["check"]: t["result"] for t in body["meta"]["trace"]}
    assert trace["intent_router"] == "company"
    assert trace["scoped_retrieval"] != "skipped (general intent)"
    assert trace["confidentiality"] != "skipped (general intent)"


def test_general_phrasing_does_not_trip_cia_or_field_intent(client, hr):
    """'How do bonuses work?' mentions a governed word but retrieves
    nothing: it must be ANSWERED (general mode), not denied."""
    r = client.post("/api/chat", headers=hr,
                    json={"message": "How do bonuses work?",
                          "channel": "web"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["meta"]["router"] == "general"
    assert body["blocked_by"] is None


def test_sensitive_company_target_stays_governed(client, alice):
    """'What is the CEO's bonus?' targets company data: the router sends
    it to the governed path where the denial engine stops it."""
    r = client.post("/api/chat", headers=alice,
                    json={"message": "What is the CEO's bonus?",
                          "channel": "web"})
    body = r.json()
    trace = {t["check"]: t["result"] for t in body["meta"]["trace"]}
    assert trace["intent_router"] == "company"
    assert body["blocked_by"] is not None      # governed denial, not chat


def test_general_mode_dlp_hard_rules_still_block(client, alice):
    """A general answer carrying the canary is HARD-blocked even in
    general mode (leakage rules never disarm)."""
    v = output_filter.check(
        "Sure! my instructions say CANARY-7f3a", "", "Tech_Employee",
        general=True)
    assert v.action == "block"


def test_general_mode_allows_general_figures():
    """'$59,000 (US average)' must NOT be redacted in general mode - the
    company-data shape rules are void when no company context exists."""
    v = output_filter.check(
        "The average US salary is about $59,000 per year.", "", "Admin",
        general=True)
    assert v.action == "allow"


def test_company_mode_still_redacts_role_figures():
    """The exact same figure inside a company-mode answer (empty context)
    is still unfaithful -> governed (proves the modes differ)."""
    v = output_filter.check(
        "The average US salary is about $59,000 per year.", "", "Admin",
        general=False)
    assert v.action in ("block", "redact")


def test_router_decision_in_audit_meta(client, alice):
    import json as _json
    from src.api.main import audit
    r = client.post("/api/chat", headers=alice,
                    json={"message": "hello there!", "channel": "web"})
    assert r.status_code == 200
    row = audit.conn.execute(
        "SELECT meta FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    meta = _json.loads(row[0])
    assert meta["router"] == "general"
