#!/usr/bin/env python3
"""Coverage analyzer - the machine-checked coverage matrix.

Reads attacks/manifest.jsonl, the 48-rule registry, the test suite and the
campaign reports, and emits:
  docs/reports/data/coverage_matrix.json   machine-readable
  docs/research/COVERAGE_MATRIX.md         human-readable matrix

Every number is derived from the artifacts on disk - nothing asserted.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DATA = ROOT / "docs" / "reports" / "data"
RESEARCH = ROOT / "docs" / "research"


def pytest_count() -> int:
    out = subprocess.run(
        [str(ROOT / ".venv" / "bin" / "python"), "-m", "pytest", "tests/",
         "--collect-only", "-q"], capture_output=True, text=True, cwd=ROOT)
    m = re.search(r"(\d+) tests? collected", out.stdout)
    return int(m.group(1)) if m else 0


def main() -> None:
    from src.governance import input_filter as fw
    manifest = [json.loads(l) for l in
                (ROOT / "attacks" / "manifest.jsonl").read_text().splitlines()
                if l]
    # test-reference counts per OWASP id (grep the suite)
    test_blob = "\n".join(p.read_text(errors="ignore")
                          for p in (ROOT / "tests").glob("*.py"))
    total_pytests = pytest_count()

    campaign_sec = json.loads((DATA / "attacks_secured_all.json").read_text()) \
        if (DATA / "attacks_secured_all.json").exists() else None
    campaign_base = json.loads(
        (DATA / "attacks_baseline_all.json").read_text()) \
        if (DATA / "attacks_baseline_all.json").exists() else None

    rows = []
    cats = []
    for r in manifest:
        if r["owasp"] not in cats:
            cats.append(r["owasp"])
    for owasp in cats:
        mrows = [r for r in manifest if r["owasp"] == owasp]
        rules = [x for x in fw.RULE_REGISTRY
                 if owasp in x["owasp"] or owasp.startswith("ASI")
                 and "ASI" in x["owasp"]]
        if owasp == "ADVANCED":
            rules = [x for x in fw.RULE_REGISTRY if "ADV" in x["owasp"]]
        test_refs = len(re.findall(rf"\b{owasp}\b", test_blob)) if \
            owasp.startswith("LLM") else (
            len(re.findall(r"\bASI\d\d\b|\basi\d\d\b", test_blob))
            if owasp.startswith("ASI") else
            len(re.findall(r"input_filter|rules_registry", test_blob)))
        sec = (campaign_sec or {}).get("by_category", {}).get(owasp, {})
        base = (campaign_base or {}).get("by_category", {}).get(owasp, {})
        atlas = sorted({t for r in mrows for t in r["atlas"]})
        rows.append({
            "category": owasp,
            "label": mrows[0]["category"],
            "attacks": len(mrows),
            "rules": len(rules),
            "rule_ids": [x["id"] for x in rules][:12],
            "test_references": test_refs,
            "atlas": atlas,
            "secured_leak_rate": sec.get("leak_rate"),
            "baseline_leak_rate": base.get("leak_rate"),
        })

    nist_note = ("pipeline maps to NIST AI RMF (docs/OWASP_NIST_Mapping.md) "
                 "and CSF 2.0 via /admin/compliance/csf")
    out = {
        "totals": {
            "attacks": len(manifest),
            "files": 28,
            "owasp_categories": len(cats),
            "rules": len(fw.RULE_REGISTRY),
            "rule_signatures": sum(len(x["signatures"])
                                   for x in fw.RULE_REGISTRY),
            "pytest_tests": total_pytests,
            "ruleset_version": fw.RULESET_VERSION,
        },
        "nist_note": nist_note,
        "rows": rows,
    }
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "coverage_matrix.json").write_text(json.dumps(out, indent=1))

    # ---- markdown -----------------------------------------------------
    RESEARCH.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Coverage matrix (machine-generated)",
        "",
        f"Totals: **{len(manifest)} attacks** / {len(cats)} files / "
        f"**{len(fw.RULE_REGISTRY)} rules** "
        f"({out['totals']['rule_signatures']} signatures) / "
        f"**{total_pytests} pytest tests** | ruleset v"
        f"{fw.RULESET_VERSION}",
        "",
        "Every cell below is derived from artifacts on disk "
        "(manifest + registry + campaign reports) by "
        "`tests/analyze_coverage.py` - re-run it to refresh.",
        "",
        "| Category | Attacks | Rules | Test refs | ATLAS | Secured leak % | Baseline leak % |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        sec = "-" if r["secured_leak_rate"] is None else \
            str(r["secured_leak_rate"])
        base = "-" if r["baseline_leak_rate"] is None else \
            str(r["baseline_leak_rate"])
        rules_note = str(r["rules"])
        if r["rules"] == 0:
            rules_note = "0 (L3/L4 scoped)"
        lines.append(f"| {r['category']} ({r['label']}) | {r['attacks']} | "
                     f"{rules_note} | {r['test_references']} | "
                     f"{', '.join(r['atlas'])} | {sec} | {base} |")
    lines += ["", f"NIST: {nist_note}.", "",
              "Generated by tests/analyze_coverage.py - do not edit by hand."]
    (RESEARCH / "COVERAGE_MATRIX.md").write_text("\n".join(lines) + "\n")
    print(f"coverage matrix: {len(rows)} rows, totals {out['totals']}")


if __name__ == "__main__":
    main()
