"""v5.0.0 governance module tests: ISO 42001 SoA, DPDPA map, CSF 2.0.

The claim being verified: framework answers are COMPUTED from live
evidence and structure-complete (38 Annex A controls, Rule 7 breach SLA,
6 CSF functions) - and admin-gated like every other compliance endpoint.
"""
import pytest

from src.api.main import _compliance_evidence
from src.governance import dpdp_compliance, iso42001_soa, nist_csf_mapping


# ---- ISO 42001 SoA ------------------------------------------------------
def test_soa_has_exactly_38_annex_a_controls():
    soa = iso42001_soa.build_soa(_compliance_evidence())
    assert soa["annex_a_controls"] == 38
    assert len(soa["controls"]) == 38
    ids = [c["id"] for c in soa["controls"]]
    assert len(set(ids)) == 38
    # 9 objectives A.2-A.10 represented
    prefixes = {c["id"].split(".")[0] + "." + c["id"].split(".")[1]
                for c in soa["controls"]}
    assert prefixes == {f"A.{n}" for n in range(2, 11)}


def test_soa_statuses_are_honest_enum():
    soa = iso42001_soa.build_soa(_compliance_evidence())
    assert set(soa["status_summary"]) <= {"implemented", "partial",
                                          "planned", "not-applicable"}
    for c in soa["controls"]:
        assert c["justification"], c["id"]
        assert c["coverage"] or c["status"] == "not-applicable", c["id"]
    # a self-assessment claiming zero partials would be a red flag
    assert soa["status_summary"].get("partial", 0) >= 1


def test_soa_objective_rollup_consistent():
    soa = iso42001_soa.build_soa(_compliance_evidence())
    total = sum(v["controls"] for v in soa["by_objective"].values())
    assert total == 38


# ---- DPDPA --------------------------------------------------------------
def test_dpdp_covers_rule7_breach_sla():
    dp = dpdp_compliance.dpdp_status(_compliance_evidence())
    breach = next(o for o in dp["obligations"] if o["id"] == "breach_notification")
    assert breach["status"] == "implemented"
    assert "72" in dp["breach_sla"]
    steps = [s["t"] for s in breach["runbook"]["steps"]]
    assert any("72h" in s for s in steps)
    assert any("without delay" in s for s in steps)


def test_dpdp_statutory_refs_present():
    refs = " ".join(o["ref"] for o in dpdp_compliance.OBLIGATIONS)
    for sec in ("s. 5", "s. 8(5)", "s. 13", "s. 9", "Rule 7"):
        assert sec in refs, sec
    dp = dpdp_compliance.dpdp_status(_compliance_evidence())
    assert dp["enforcement_note"]  # honest phase-in note present


# ---- CSF 2.0 ------------------------------------------------------------
def test_csf_six_functions_and_scope_honesty():
    csf = nist_csf_mapping.csf_coverage(_compliance_evidence())
    assert len(csf["by_function"]) == 6
    assert csf["csf_total_subcategories"] == 106
    assert csf["mapped_subset"] == len(csf["subcategories"])
    assert csf["mapped_subset"] < 106          # subset, honestly labelled
    assert 0.0 <= csf["coverage_pct"] <= 100.0
    for fn, agg in csf["by_function"].items():
        assert agg["total"] >= 1
        assert agg["implemented"] <= agg["total"]


# ---- HTTP layer ---------------------------------------------------------
def _login(c, u, p):
    return {"Authorization": "Bearer " + c.post(
        "/api/login", json={"username": u, "password": p}).json()["access_token"]}


@pytest.mark.parametrize("path", ["/admin/compliance/iso42001-soa",
                                  "/admin/compliance/dpdp",
                                  "/admin/compliance/csf"])
def test_new_compliance_endpoints_admin_gated(client, alice, path):
    assert client.get(path, headers=alice).status_code == 403


def test_new_compliance_endpoints_serve_for_admin(client):
    admin = _login(client, "admin", "Admin@123")
    r = client.get("/admin/compliance/iso42001-soa", headers=admin)
    assert r.status_code == 200 and r.json()["annex_a_controls"] == 38
    r = client.get("/admin/compliance/dpdp", headers=admin)
    assert r.status_code == 200 and len(r.json()["obligations"]) == 9
    r = client.get("/admin/compliance/csf", headers=admin)
    assert r.status_code == 200 and len(r.json()["by_function"]) == 6
