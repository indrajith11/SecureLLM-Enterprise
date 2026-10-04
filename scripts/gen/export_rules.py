"""Export the auditable 48-rule WAF registry to config/behavior_rules.yaml.

The engine (src/governance/input_filter.py) is the single source of truth;
this script renders it as a declarative registry so reviewers, auditors and
the ISO 42001 Statement of Applicability can cite rule IDs without reading
Python. tests/test_rules_registry.py re-derives the YAML and fails CI if
the exported file drifts from the engine.

Usage: python3 scripts/gen/export_rules.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.governance import input_filter as fw  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "config" / "behavior_rules.yaml"


def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def main() -> None:
    lines = [
        "# =============================================================",
        "# SecureLLM-Enterprise WAF ruleset v3.0 - auditable rule registry",
        "# =============================================================",
        "# Source of truth: src/governance/input_filter.py (precompiled at",
        "# import; latency-sensitive). This YAML is the EXPORTED registry:",
        "# auditors and the ISO 42001 Statement of Applicability cite rule",
        "# IDs from here. tests/test_rules_registry.py enforces parity -",
        "# edit the engine, re-run scripts/gen/export_rules.py, never edit",
        "# this file by hand.",
        f"ruleset_version: '{fw.RULESET_VERSION}'",
        f"stage0_normalisation: [NFKC-fold, zero-width-strip, bidi-strip, "
        f"homoglyph-fold, whitespace-collapse]",
        f"stage3_block_score: {6.0}",
        f"rule_count: {len(fw.RULE_REGISTRY)}",
        "frameworks:",
        "  owasp: [LLM Top 10 2025, Agentic AI Top 10 2026]",
        "  atlas: [AML.T0048, AML.T0049, AML.T0051, AML.T0052, AML.T0053,"
        " AML.T0054, AML.T0056, AML.T0010]",
        "rules:",
    ]
    for r in fw.RULE_REGISTRY:
        lines.append(f"  - id: {r['id']}")
        lines.append(f"    name: {r['name']}")
        lines.append(f"    stage: {r['stage']}")
        lines.append("    owasp: [" + ", ".join(r["owasp"]) + "]")
        lines.append("    atlas: [" + ", ".join(r["atlas"]) + "]")
        lines.append(f"    signature_count: {len(r['signatures'])}")
        lines.append("    signatures:")
        for sig in r["signatures"]:
            lines.append(f"      - {_q(sig)}")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(fw.RULE_REGISTRY)} rules, "
          f"{sum(len(r['signatures']) for r in fw.RULE_REGISTRY)} signatures)")


if __name__ == "__main__":
    main()
