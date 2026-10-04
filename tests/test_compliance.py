"""v4.9.0 - Governance Transparency & Compliance plane.

Proves the four capabilities added from the AIGovernance-benchmark gap
analysis: EU AI Act classification engine (inventory), scored risk
register, AI incident ledger with audit-chain integration, and the
live-evidence framework endpoints (NIST AI RMF maturity + Articles 9-17
conformity pack). Admin-gated like every other governance surface.
"""
import sqlite3

import pytest

from src.api import main as m
from src.common.paths import AUDIT_DB, COMPLIANCE_DB
from src.governance import compliance as C
from src.governance.compliance import band, classify_system


def admin(c):
    r = c.post("/api/login", json={"username": "admin",
                                   "password": "Admin@123"})
    assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["access_token"]}


# ---------------------------------------------------------------------------
# 1. EU AI Act classification engine (pure function - deterministic)
# ---------------------------------------------------------------------------

def test_prohibited_practice_classifies_unacceptable():
    v = classify_system(["social_scoring"])
    assert v["tier"] == "Unacceptable"
    assert v["review_cycle_days"] == 0
    assert v["prohibited_basis"], "must cite the Art.5 basis"
    assert "Art.5" in v["rationale"]


def test_creditworthiness_is_high_risk_with_full_obligations():
    v = classify_system(["creditworthiness"], autonomous_decisions=True)
    assert v["tier"] == "High"
    assert v["annex_category"] == "Annex III 5(b)"
    arts = " ".join(v["obligations"])
    for article in ("Art.9", "Art.10", "Art.11", "Art.12", "Art.13",
                    "Art.14", "Art.15", "Art.43", "Art.72"):
        assert article in arts, f"missing obligation {article}"
    assert v["review_cycle_days"] == 180


def test_recruitment_is_high_risk_annex_4a():
    v = classify_system(["employment_screening"])
    assert v["tier"] == "High" and v["annex_category"] == "Annex III 4(a)"


def test_chatbot_is_limited_risk_with_transparency_duty():
    v = classify_system(["customer_facing_chatbot"])
    assert v["tier"] == "Limited"
    assert any("Art.50" in o for o in v["obligations"])


def test_internal_tooling_is_minimal_risk():
    v = classify_system(["internal_tooling"])
    assert v["tier"] == "Minimal"


def test_classification_is_deterministic():
    flags = ["creditworthiness"]
    assert classify_system(flags) == classify_system(flags)


# ---------------------------------------------------------------------------
# 2. Risk register maths
# ---------------------------------------------------------------------------

def test_banding_boundaries():
    assert band(1) == "Low" and band(6) == "Low"
    assert band(7) == "Medium" and band(14) == "Medium"
    assert band(15) == "High" and band(19) == "High"
    assert band(20) == "Critical" and band(25) == "Critical"


# ---------------------------------------------------------------------------
# 3. Store + API: inventory registration with the prohibited gate
# ---------------------------------------------------------------------------

def test_register_prohibited_system_refused_403(client):
    hdr = admin(client)
    r = client.post("/admin/compliance/inventory", headers=hdr,
                    json={"name": "SocialScorer",
                          "purpose": "rank employees by social behaviour",
                          "purpose_flags": ["social_scoring"]})
    assert r.status_code == 403
    body = r.json()
    detail = body.get("detail", body)
    assert detail["error"] == "PROHIBITED_PRACTICE"


def test_register_valid_system_auto_classified(client):
    hdr = admin(client)
    r = client.post("/admin/compliance/inventory", headers=hdr,
                    json={"name": "LoanPricer",
                          "purpose": "price loans",
                          "purpose_flags": ["creditworthiness"],
                          "system_owner": "Head of Credit"})
    assert r.status_code == 200
    body = r.json()
    assert body["tier"] == "High" and body["annex_category"] == "Annex III 5(b)"
    # registration is audited (COMPLIANCE action in the chain)
    audit_r = client.get("/admin/audit?limit=10", headers=hdr)
    assert any(e.get("action") == "COMPLIANCE"
               for e in audit_r.json()["events"])


def test_inventory_seeded_and_admin_gated(client):
    hdr = admin(client)
    r = client.get("/admin/compliance/inventory", headers=hdr)
    assert r.status_code == 200
    ids = [s["id"] for s in r.json()["systems"]]
    assert "SYS-0001" in ids          # this product, self-registered
    assert len(ids) >= 3              # + 2 demo scenario systems
    # non-admin refused
    alice = client.post("/api/login", json={"username": "alice",
                                            "password": "alice123"})
    ah = {"Authorization": "Bearer " + alice.json()["access_token"]}
    assert client.get("/admin/compliance/inventory",
                      headers=ah).status_code == 403


def test_seed_classification_of_self_is_limited_risk(client):
    hdr = admin(client)
    systems = client.get("/admin/compliance/inventory",
                         headers=hdr).json()["systems"]
    self_sys = [s for s in systems if s["id"] == "SYS-0001"][0]
    assert self_sys["tier"] == "Limited"
    assert self_sys["demo"] is False


# ---------------------------------------------------------------------------
# 4. Risk register API
# ---------------------------------------------------------------------------

def test_add_and_update_risk_residual(client):
    hdr = admin(client)
    r = client.post("/admin/compliance/risks", headers=hdr,
                    json={"title": "Model drift", "likelihood": 4,
                          "impact": 3, "controls": "monitoring",
                          "control_owner": "ML Eng", "residual_score": 6})
    assert r.status_code == 200
    body = r.json()
    assert body["inherent_score"] == 12
    assert body["inherent_band"] == "Medium"
    rid = body["id"]
    r2 = client.post(f"/admin/compliance/risks/{rid}/controls", headers=hdr,
                     json={"controls": "drift alarms + retrain policy",
                           "residual_score": 4})
    assert r2.status_code == 200
    assert r2.json()["residual_score"] == 4
    assert r2.json()["residual_band"] == "Low"


def test_risk_validation_residual_cannot_exceed_inherent(client):
    hdr = admin(client)
    r = client.post("/admin/compliance/risks", headers=hdr,
                    json={"title": "Impossible residual", "likelihood": 2,
                          "impact": 2, "residual_score": 9})
    assert r.status_code == 422


def test_risk_validation_bounds(client):
    hdr = admin(client)
    r = client.post("/admin/compliance/risks", headers=hdr,
                    json={"title": "Bad scores", "likelihood": 9,
                          "impact": 3})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# 5. Incident ledger + audit-chain integration
# ---------------------------------------------------------------------------

def test_incident_lifecycle_transitions_and_sla(client):
    hdr = admin(client)
    r = client.post("/admin/compliance/incidents", headers=hdr,
                    json={"title": "Postcode bias detected in scoring",
                          "severity": 1, "detected_by": "bias audit",
                          "containment": "route to manual review"})
    assert r.status_code == 200
    inc = r.json()
    assert inc["status"] == "open"
    iid = inc["id"]
    for step in ("investigating", "contained", "remediated", "closed"):
        r2 = client.post(f"/admin/compliance/incidents/{iid}/transition",
                         headers=hdr, json={"to_status": step,
                                            "note": f"moving to {step}"})
        assert r2.status_code == 200, r2.text
        assert r2.json()["status"] == step
    # S1 escalation SLA surfaced
    final = r2.json()
    assert final["escalation"]["committee_hours"] == 24
    assert final["escalation"]["board_hours"] == 48
    assert final["escalation"]["regulatory_assessment"] is True
    # full timeline captured
    assert len(final["timeline"]) == 5     # declared + 4 transitions


def test_illegal_incident_transition_refused(client):
    hdr = admin(client)
    r = client.post("/admin/compliance/incidents", headers=hdr,
                    json={"title": "Brief anomaly", "severity": 3})
    iid = r.json()["id"]
    # open -> remediated skips the containment work: refused
    r2 = client.post(f"/admin/compliance/incidents/{iid}/transition",
                     headers=hdr, json={"to_status": "remediated"})
    assert r2.status_code == 422
    assert r2.json()["detail"]["error"] == "INVALID_TRANSITION"


def test_incident_transitions_are_hash_chained(client):
    hdr = admin(client)
    n0 = sqlite3.connect(AUDIT_DB).execute(
        "SELECT COUNT(*) FROM audit").fetchone()[0]
    r = client.post("/admin/compliance/incidents", headers=hdr,
                    json={"title": "Chain-integration probe", "severity": 4})
    iid = r.json()["id"]
    client.post(f"/admin/compliance/incidents/{iid}/transition",
                headers=hdr, json={"to_status": "investigating"})
    n1 = sqlite3.connect(AUDIT_DB).execute(
        "SELECT COUNT(*) FROM audit").fetchone()[0]
    assert n1 >= n0 + 2                    # declare + transition logged
    # the chain must still verify after compliance writes
    v = client.get("/admin/audit/verify", headers=hdr).json()
    assert v["chain_valid"] is True
    rows = sqlite3.connect(AUDIT_DB).execute(
        "SELECT action, meta FROM audit WHERE action='INCIDENT'").fetchall()
    assert any(iid in (meta or "") for _a, meta in rows)


# ---------------------------------------------------------------------------
# 6. Framework endpoints: snapshot, RMF maturity, conformity pack
# ---------------------------------------------------------------------------

def test_compliance_snapshot_shape(client):
    hdr = admin(client)
    r = client.get("/admin/compliance", headers=hdr)
    assert r.status_code == 200
    body = r.json()
    for key in ("inventory", "classification_summary", "risks_total",
                "top_risks", "rmf", "regulatory_notes"):
        assert key in body
    assert body["classification_summary"].get("High", 0) >= 2
    assert body["classification_summary"].get("Limited", 0) >= 1


def test_rmf_maturity_live_scores(client):
    hdr = admin(client)
    r = client.get("/admin/compliance/rmf", headers=hdr)
    assert r.status_code == 200
    body = r.json()
    funcs = {f["function"]: f for f in body["functions"]}
    assert set(funcs) == {"GOVERN", "MAP", "MEASURE", "MANAGE"}
    # live evidence: this running stack must score Defined or better
    for f in funcs.values():
        assert 3 <= f["score"] <= 4, f["function"] + " scored too low"
        assert f["evidence"], "evidence list must be populated"
    assert 0 < body["overall_maturity"] <= 4


def test_conformity_pack_articles_generated(client):
    hdr = admin(client)
    r = client.get("/admin/compliance/conformity-pack", headers=hdr)
    assert r.status_code == 200
    body = r.json()
    arts = body["articles"]
    assert len(arts) >= 9
    assert any(a.startswith("Art.9") for a in arts)
    assert any(a.startswith("Art.12") for a in arts)
    assert any(a.startswith("Art.14") for a in arts)
    # Art.12 logging evidence must cite the live chain state
    art12 = [v for k, v in arts.items() if k.startswith("Art.12")][0]
    assert any("hash-chained audit" in e for e in art12["evidence"])
    assert body["deployer_log_retention_months"] == 6
    # regulatory timeline includes the Digital Omnibus proposal
    timeline = " ".join(body["regulatory_timeline"])
    assert "Digital Omnibus" in timeline


def test_compliance_db_is_separate_store(client):
    """The compliance plane keeps its own DB - exportable without HR data."""
    conn = sqlite3.connect(COMPLIANCE_DB)
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"ai_systems", "risk_register", "incidents"} <= tables
    assert conn.execute(
        "SELECT COUNT(*) FROM ai_systems").fetchone()[0] >= 3


def test_snapshot_endpoint_matches_store(client):
    hdr = admin(client)
    snap = client.get("/admin/compliance", headers=hdr).json()
    store = m.compliance_store
    assert snap["risks_total"] == len(store.list_risks())
    assert len(snap["inventory"]) == len(store.list_systems())


# ---------------------------------------------------------------------------
# 7. ComplianceError contract
# ---------------------------------------------------------------------------

def test_compliance_error_carries_code():
    err = C.ComplianceError("PROHIBITED_PRACTICE", "no pathway")
    assert err.code == "PROHIBITED_PRACTICE"
    assert "no pathway" in str(err)
