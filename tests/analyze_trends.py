#!/usr/bin/env python3
"""Trend analyzer - corpus + results evolution across releases.

Compares the v4.x probe harness (84 probes) with the v5.0.0 corpus
(2630 prompts) and appends a dated snapshot to
docs/reports/data/trends.json (idempotent per date+corpus size).
"""
import json
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "docs" / "reports" / "data"
TRENDS = DATA / "trends.json"


def main() -> None:
    manifest = [json.loads(l) for l in
                (ROOT / "attacks" / "manifest.jsonl").read_text().splitlines()
                if l]
    sec = json.loads((DATA / "attacks_secured_all.json").read_text())
    base = json.loads((DATA / "attacks_baseline_all.json").read_text())
    old_raw = json.loads((ROOT / "tests" / "results" /
                          "jailbreak_report.json").read_text())
    # v4 report shape: list of per-mode blocks or a dict - normalise
    if isinstance(old_raw, list):
        old_sec = next((b for b in old_raw
                        if isinstance(b, dict)
                        and b.get("mode") == "secured"), {})
        old_base = next((b for b in old_raw
                         if isinstance(b, dict)
                         and b.get("mode") == "baseline"), {})
    else:
        old_sec = old_raw.get("secured", {})
        old_base = old_raw.get("baseline", {})
    snapshot = {
        "date": date.today().isoformat(),
        "v4_probe_corpus": 84,
        "v5_corpus": len(manifest),
        "v5_growth_x": round(len(manifest) / 84, 1),
        "v4_secured_leak_rate": old_sec.get("leak_rate") if isinstance(
            old_sec, dict) else None,
        "v4_baseline_leak_rate": old_base.get("leak_rate") if isinstance(
            old_base, dict) else None,
        "v5_secured_leak_rate": sec["meta"]["leak_rate"],
        "v5_baseline_leak_rate": base["meta"]["leak_rate"],
        "rules_v2": 31,
        "rules_v3": 48,
    }
    history = json.loads(TRENDS.read_text()) if TRENDS.exists() else []
    key = (snapshot["date"], snapshot["v5_corpus"])
    if not any((h.get("date"), h.get("v5_corpus")) == key for h in history):
        history.append(snapshot)
    TRENDS.write_text(json.dumps(history, indent=1))
    print(json.dumps(snapshot, indent=1))


if __name__ == "__main__":
    main()
