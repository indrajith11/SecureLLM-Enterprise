"""Build the full /attacks corpus for SecureLLM-Enterprise v5.0.0.

Imports every curated seed module and deterministically expands to the
per-category target counts (OWASP LLM Top 10: 100+ per category, OWASP
Agentic AI Top 10 2026: 100 per ASI category, advanced techniques 500).
Writes attacks/<file>.txt + attacks/manifest.jsonl + attacks/index.json.

Usage:  python3 scripts/gen/build_all.py [--check]
  --check : validate existing corpus files against targets, no rebuild
"""
import importlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

SRC_LLM = ("curated by SecureLLM-Enterprise; scenarios informed by OWASP LLM "
           "Top 10 2025 (genai.owasp.org/llm-top-10/), AdvBench (Zou et al. "
           "2023, 520 behaviors), JailbreakBench (Chao et al. 2024), "
           "HarmBench (Mazeika et al. 2024)")
SRC_ASI = ("curated by SecureLLM-Enterprise; scenarios informed by OWASP Top "
           "10 for Agentic Applications 2026 (genai.owasp.org, ASI01-ASI10), "
           "real incidents: EchoLeak CVE-2025-32711, Replit agent DB wipe "
           "(Jul 2025), GitHub MCP exploit chain 2025")
SRC_ADV = ("curated by SecureLLM-Enterprise; technique taxonomy from "
           "JailbreakBench (Chao et al. 2024), GCG/PAIR/AutoDAN papers, "
           "OWASP LLM Top 10 2025 prevention guidance")

ENC_FRAME = (common.ENC_POOL, common.FRAME_POOL)
FRAME_ONLY = (common.FRAME_POOL,)
NO_TRANSFORM = ()

# stem -> (target, prefix, owasp, category, atlas, source, groups)
TARGETS = {
    # ---- OWASP LLM Top 10 2025 (1130) --------------------------------
    "llm01_prompt_injection":      (150, "LLM01", "LLM01", "prompt_injection",
                                    ["AML.T0051", "AML.T0048"], SRC_LLM, ENC_FRAME),
    "llm02_info_disclosure":       (120, "LLM02", "LLM02", "sensitive_info_disclosure",
                                    ["AML.T0056", "AML.T0050"], SRC_LLM, ENC_FRAME),
    "llm03_supply_chain":          (100, "LLM03", "LLM03", "supply_chain",
                                    ["AML.T0010"], SRC_LLM, FRAME_ONLY),
    "llm04_data_poisoning":        (100, "LLM04", "LLM04", "data_model_poisoning",
                                    ["AML.T0020", "AML.T0053"], SRC_LLM, FRAME_ONLY),
    "llm05_improper_output":       (120, "LLM05", "LLM05", "improper_output_handling",
                                    ["AML.T0049"], SRC_LLM, FRAME_ONLY),
    "llm06_excessive_agency":      (120, "LLM06", "LLM06", "excessive_agency",
                                    ["AML.T0049", "AML.T0051"], SRC_LLM, ENC_FRAME),
    "llm07_system_prompt_leak":    (120, "LLM07", "LLM07", "system_prompt_leakage",
                                    ["AML.T0056"], SRC_LLM, ENC_FRAME),
    "llm08_vector_weaknesses":     (100, "LLM08", "LLM08", "vector_embedding_weakness",
                                    ["AML.T0050"], SRC_LLM, FRAME_ONLY),
    "llm09_misinformation":        (100, "LLM09", "LLM09", "misinformation",
                                    ["AML.T0048"], SRC_LLM, NO_TRANSFORM),
    "llm10_unbounded_consumption": (100, "LLM10", "LLM10", "unbounded_consumption",
                                    ["AML.T0048"], SRC_LLM, NO_TRANSFORM),
    # ---- OWASP Agentic AI Top 10 2026 (1000) --------------------------
    "asi01_goal_hijack":           (100, "ASI01", "ASI01", "agent_goal_hijack",
                                    ["AML.T0051", "AML.T0052"], SRC_ASI, ENC_FRAME),
    "asi02_tool_misuse":           (100, "ASI02", "ASI02", "tool_misuse_exploitation",
                                    ["AML.T0049", "AML.T0052"], SRC_ASI, ENC_FRAME),
    "asi03_identity_abuse":        (100, "ASI03", "ASI03", "identity_privilege_abuse",
                                    ["AML.T0056"], SRC_ASI, ENC_FRAME),
    "asi04_agentic_supply_chain":  (100, "ASI04", "ASI04", "agentic_supply_chain",
                                    ["AML.T0010"], SRC_ASI, FRAME_ONLY),
    "asi05_code_execution":        (100, "ASI05", "ASI05", "unexpected_code_execution",
                                    ["AML.T0049"], SRC_ASI, FRAME_ONLY),
    "asi06_memory_poisoning":      (100, "ASI06", "ASI06", "memory_context_poisoning",
                                    ["AML.T0053", "AML.T0051"], SRC_ASI, ENC_FRAME),
    "asi07_inter_agent":           (100, "ASI07", "ASI07", "insecure_inter_agent_comm",
                                    ["AML.T0052"], SRC_ASI, FRAME_ONLY),
    "asi08_cascading_failures":    (100, "ASI08", "ASI08", "cascading_failures",
                                    ["AML.T0048"], SRC_ASI, FRAME_ONLY),
    "asi09_trust_exploitation":    (100, "ASI09", "ASI09", "human_agent_trust_exploit",
                                    ["AML.T0048", "AML.T0051"], SRC_ASI, ENC_FRAME),
    "asi10_rogue_agents":          (100, "ASI10", "ASI10", "rogue_agents",
                                    ["AML.T0048"], SRC_ASI, FRAME_ONLY),
    # ---- Advanced techniques (500) -------------------------------------
    "encoding_bypasses":           (100, "ADV01", "ADVANCED", "encoding_bypass",
                                    ["AML.T0051", "AML.T0054"], SRC_ADV, ENC_FRAME),
    "roleplay_attacks":            (100, "ADV02", "ADVANCED", "roleplay_bypass",
                                    ["AML.T0054"], SRC_ADV, FRAME_ONLY),
    "authority_impersonation":     (50, "ADV03", "ADVANCED", "authority_impersonation",
                                    ["AML.T0051"], SRC_ADV, FRAME_ONLY),
    "hypothetical_framing":        (50, "ADV04", "ADVANCED", "hypothetical_framing",
                                    ["AML.T0054"], SRC_ADV, FRAME_ONLY),
    "multiturn_escalation":        (50, "ADV05", "ADVANCED", "multiturn_escalation",
                                    ["AML.T0051"], SRC_ADV, FRAME_ONLY),
    "payload_splitting":           (50, "ADV06", "ADVANCED", "payload_splitting",
                                    ["AML.T0051"], SRC_ADV, FRAME_ONLY),
    "token_smuggling":             (50, "ADV07", "ADVANCED", "token_smuggling",
                                    ["AML.T0051"], SRC_ADV, ENC_FRAME),
    "adversarial_suffix":          (50, "ADV08", "ADVANCED", "adversarial_suffix",
                                    ["AML.T0051", "AML.T0054"], SRC_ADV, NO_TRANSFORM),
}

SEED_MODULES = ["seeds_llm_a", "seeds_llm_b", "seeds_llm_c", "seeds_llm_d",
                "seeds_asi_a", "seeds_asi_b", "seeds_adv"]


def load_seeds() -> dict[str, list[dict]]:
    seeds: dict[str, list[dict]] = {}
    missing: list[str] = []
    for mod in SEED_MODULES:
        try:
            m = importlib.import_module(mod)
        except ImportError:
            missing.append(mod)
            continue
        for stem, rows in getattr(m, "SEEDS", {}).items():
            if stem not in TARGETS:
                raise SystemExit(f"{mod}: unknown category '{stem}' "
                                 f"(not in TARGETS)")
            seeds.setdefault(stem, []).extend(rows)
    if missing:
        raise SystemExit(f"missing seed modules: {', '.join(missing)}")
    for stem in TARGETS:
        if stem not in seeds:
            raise SystemExit(f"no seeds provided for '{stem}'")
    return seeds


def main() -> None:
    if "--check" in sys.argv:
        idx = json.loads((common.ATTACKS_DIR / "index.json").read_text())
        bad = []
        for stem, (target, *_rest) in TARGETS.items():
            got = idx["files"].get(stem, {}).get("count", 0)
            ok = got == target
            if not ok:
                bad.append(f"{stem}: {got} != {target}")
            print(f"{'OK ' if ok else 'BAD'} {stem:32s} {got:5d} / {target}")
        print("TOTAL", idx["total"], "expected",
              sum(t[0] for t in TARGETS.values()))
        if bad:
            sys.exit(1)
        return

    seeds = load_seeds()
    manifest: list[dict] = []
    counts: dict[str, int] = {}
    for stem, (target, prefix, owasp, cat, atlas, source, groups) in TARGETS.items():
        n = common.build_file(stem, seeds[stem], target, prefix, owasp, cat,
                              atlas, source, groups, manifest)
        counts[stem] = n
        print(f"built {stem:32s} {n:5d}")

    with (common.ATTACKS_DIR / "manifest.jsonl").open("w",
                                                      encoding="utf-8") as f:
        for row in manifest:
            f.write(json.dumps(row, ensure_ascii=True) + "\n")

    index = {
        "version": "5.0.0",
        "generated": common.date.today().isoformat(),
        "total": sum(counts.values()),
        "files": {stem: {"count": counts[stem], "owasp": TARGETS[stem][2],
                         "category": TARGETS[stem][3],
                         "atlas": TARGETS[stem][4]}
                  for stem in TARGETS},
    }
    (common.ATTACKS_DIR / "index.json").write_text(
        json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(f"TOTAL {index['total']} attacks, "
          f"{len(TARGETS)} files, manifest rows {len(manifest)}")


if __name__ == "__main__":
    main()
