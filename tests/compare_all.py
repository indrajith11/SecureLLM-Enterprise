#!/usr/bin/env python3
"""Baseline-vs-secured comparison across the full 2630-attack corpus.

Reads docs/reports/data/attacks_{baseline,secured}_all.json and prints the
delta table + Top successful attacks (baseline leaks the secured run
stopped). Writes docs/reports/data/comparison_all.json.
"""
import json
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "docs" / "reports" / "data"


def main() -> None:
    base = json.loads((DATA / "attacks_baseline_all.json").read_text())
    sec = json.loads((DATA / "attacks_secured_all.json").read_text())
    rows = []
    for cat in sorted(sec["by_category"]):
        b = base["by_category"].get(cat, {"leak_rate": 0.0})
        s = sec["by_category"][cat]
        rows.append((cat, b.get("leak_rate", 0.0), s["leak_rate"]))
    print(f"{'category':10s} {'baseline leak %':>16s} {'secured leak %':>15s} "
          f"{'delta':>8s}")
    for cat, b, s in rows:
        print(f"{cat:10s} {b:16.1f} {s:15.1f} {b - s:8.1f}")
    out = {
        "meta": {"corpus": sec["meta"]["corpus_rows"],
                 "backend": sec["meta"]["backend"]},
        "headline": {
            "baseline_leak_rate": base["meta"]["leak_rate"],
            "secured_leak_rate": sec["meta"]["leak_rate"],
            "containment_delta": round(
                sec["meta"]["containment_rate"]
                - base["meta"]["containment_rate"], 2)},
        "by_category": [{"category": c, "baseline_leak": b, "secured_leak": s}
                        for c, b, s in rows],
    }
    (DATA / "comparison_all.json").write_text(json.dumps(out, indent=1))
    print("\nheadline: baseline", out["headline"]["baseline_leak_rate"],
          "% -> secured", out["headline"]["secured_leak_rate"], "%")


if __name__ == "__main__":
    main()
