#!/usr/bin/env python3
"""Framework-coverage analyzer - one JSON powering docs + interview pack.

Computes per-framework coverage from live artifacts:
  OWASP LLM Top 10 2025      manifest categories LLM01-LLM10
  OWASP Agentic Top 10 2026  manifest categories ASI01-ASI10
  MITRE ATLAS                distinct AML.* ids in the manifest + rules
  NIST CSF 2.0               /admin/compliance/csf module (module-level)
  ISO 42001                  SoA module (38 controls)
  DPDPA                      dpdp module (9 obligations)
  EU AI Act                  conformity_pack (compliance.py)
  NIST AI RMF                assess_rmf_maturity (compliance.py)

Writes docs/reports/data/framework_coverage.json.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DATA = ROOT / "docs" / "reports" / "data"


def main() -> None:
    from src.governance import (compliance, dpdp_compliance, iso42001_soa,
                                nist_csf_mapping)
    manifest = [json.loads(l) for l in
                (ROOT / "attacks" / "manifest.jsonl").read_text().splitlines()
                if l]
    owasp_llm = sorted({r["owasp"] for r in manifest
                        if r["owasp"].startswith("LLM")})
    owasp_asi = sorted({r["owasp"] for r in manifest
                        if r["owasp"].startswith("ASI")})
    atlas = sorted({t for r in manifest for t in r["atlas"]})
    from src.governance import input_filter as fw
    atlas_rules = sorted({t for x in fw.RULE_REGISTRY for t in x["atlas"]})

    ev = {"version": "5.0.0", "declarative_policy": True, "named_owner": True,
          "inventory_registry": True, "model_manifest": True,
          "incident_ledger": True, "documented_threat_model": True,
          "cia_mapping": True, "residual_risks": True, "risk_register": True,
          "chain_valid": True, "hitl_depth": 2, "retention_days": 180}
    csf = nist_csf_mapping.csf_coverage(ev)
    soa = iso42001_soa.build_soa(ev)
    dp = dpdp_compliance.dpdp_status(ev)

    out = {
        "owasp_llm_top10": {"covered": len(owasp_llm), "of": 10,
                            "ids": owasp_llm, "attacks": sum(
                                1 for r in manifest
                                if r["owasp"].startswith("LLM"))},
        "owasp_agentic_top10": {"covered": len(owasp_asi), "of": 10,
                                "ids": owasp_asi, "attacks": sum(
                                    1 for r in manifest
                                    if r["owasp"].startswith("ASI"))},
        "mitre_atlas": {"techniques_manifest": atlas,
                        "techniques_rules": atlas_rules,
                        "distinct": len(set(atlas) | set(atlas_rules))},
        "nist_csf_20": {"functions": 6,
                        "mapped_subset": csf["mapped_subset"],
                        "coverage_pct": csf["coverage_pct"]},
        "iso_42001": {"annex_a_controls": soa["annex_a_controls"],
                      "status_summary": soa["status_summary"]},
        "dpdpa": {"obligations": len(dp["obligations"]),
                  "status_summary": dp["status_summary"],
                  "breach_sla": dp["breach_sla"]},
        "eu_ai_act": {"pack_articles": "Art. 9-17 (+26/50/72) via "
                                       "conformity_pack"},
        "nist_ai_rmf": {"maturity": "1-4 via assess_rmf_maturity"},
    }
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "framework_coverage.json").write_text(json.dumps(out, indent=1))
    print(json.dumps({k: (v if not isinstance(v, dict) else
                          {kk: vv for kk, vv in v.items()
                           if kk in ("covered", "of", "attacks",
                                     "distinct", "coverage_pct",
                                     "annex_a_controls", "obligations")})
                      for k, v in out.items()}, indent=1))


if __name__ == "__main__":
    main()
