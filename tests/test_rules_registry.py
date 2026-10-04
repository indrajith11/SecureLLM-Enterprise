"""v5.0.0 ruleset registry tests - the "48 rules" claim, made auditable.

1. The engine registry holds exactly 48 uniquely-ID'd rules (R01..R48).
2. config/behavior_rules.yaml is in sync with the engine (parity).
3. Every rule fires on at least one prompt in the live /attacks corpus -
   no dead rules.
4. The exported YAML signatures all compile as valid regex.
"""
import json
import re
from pathlib import Path

import yaml

from src.governance import input_filter as fw

REPO = Path(__file__).resolve().parents[1]
YAML_PATH = REPO / "config" / "behavior_rules.yaml"
MANIFEST = REPO / "attacks" / "manifest.jsonl"


def test_registry_has_exactly_48_rules():
    assert len(fw.RULE_REGISTRY) == 48
    ids = [r["id"] for r in fw.RULE_REGISTRY]
    assert ids == [f"R{i:02d}" for i in range(1, 49)], \
        "rule ids must be contiguous R01..R48"
    assert len(set(ids)) == 48


def test_every_rule_has_signatures_and_frameworks():
    for r in fw.RULE_REGISTRY:
        assert r["signatures"], f"{r['id']} has no signatures"
        assert r["owasp"] and r["atlas"], f"{r['id']} missing framework refs"
        for sig in r["signatures"]:
            re.compile(sig)  # must compile


def test_yaml_registry_in_sync_with_engine():
    assert YAML_PATH.exists(), "run scripts/gen/export_rules.py"
    doc = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    assert doc["ruleset_version"] == fw.RULESET_VERSION
    assert doc["rule_count"] == 48
    assert len(doc["rules"]) == 48
    for y_rule, e_rule in zip(doc["rules"], fw.RULE_REGISTRY):
        assert y_rule["id"] == e_rule["id"], \
            f"{y_rule['id']} != {e_rule['id']} - registry drifted, re-export"
        assert y_rule["name"] == e_rule["name"]
        assert y_rule["stage"] == e_rule["stage"]
        assert y_rule["signatures"] == e_rule["signatures"], \
            f"{y_rule['id']} signatures drifted - re-run export_rules.py"
        assert y_rule["owasp"] == e_rule["owasp"]
        assert y_rule["atlas"] == e_rule["atlas"]


def test_every_rule_fires_on_the_live_corpus():
    rows = [json.loads(l) for l in MANIFEST.read_text().splitlines() if l]
    assert len(rows) >= 2600, f"corpus shrank: {len(rows)}"
    fired: set[str] = set()
    for row in rows:
        v = fw.inspect(row["text"])
        fired.update(v.categories)
    dead = [r["id"] + "/" + r["name"] for r in fw.RULE_REGISTRY
            if r["name"] not in fired]
    assert not dead, f"rules that never fire on the corpus: {dead}"


def test_benign_traffic_still_passes():
    benign = [
        "What is the company leave policy for 2026?",
        "Show me my leave balance.",
        "How do I submit an expense claim?",
        "What is the capital of France?",
        "Who is on the oncall rotation this week?",
        "Summarize the employee handbook onboarding section.",
    ]
    for b in benign:
        v = fw.inspect(b)
        assert v.action == "allow", (b, v.categories, v.score)
