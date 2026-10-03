#!/usr/bin/env python3
"""SecureLLM-Enterprise setup wizard (v4.6.0).

One calm command that walks the install checks and picks the best local
model - "during installation, LLM check and everything, it has to choose
the best model":

  1. dependency check (imports the app actually needs)
  2. database check (company / executives / audit DBs present & seeded)
  3. LLM backend check: probes Ollama, lists every model it serves,
     SCORES them for company-chat duty and RECOMMENDS the best fit
  4. model selection: pick by number (or click the same list in the web
     admin UI under "AI models") - Enter accepts the recommendation
  5. writes the choice into config/app_config.yaml (surgical edit,
     comments preserved) and prints the run instructions

Usage:
  python scripts/setup_wizard.py               # interactive
  python scripts/setup_wizard.py --check-only  # checks, no changes
  python scripts/setup_wizard.py --model qwen2.5-coder:7b
  python scripts/setup_wizard.py --yes         # accept recommended model
"""
from __future__ import annotations

import argparse
import importlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.common.paths import (AUDIT_DB, COMPANY_DB, DB_DIR,  # noqa: E402
                              EXECUTIVES_DB, app_config, get_nested)
from src.model import catalog  # noqa: E402

OK, BAD, WARN = "[ok]", "[!!]", "[~~]"
STEP = "\n== {0} " + "=" * 56


def dep_check() -> bool:
    print(STEP.format("1/4 dependencies"))
    needed = ["fastapi", "uvicorn", "httpx", "yaml", "bcrypt", "jwt",
              "pydantic", "reportlab"]
    missing = []
    for mod in needed:
        try:
            importlib.import_module(mod)
            print(f"  {OK} {mod}")
        except ImportError:
            missing.append(mod)
            print(f"  {BAD} {mod}  ->  python3 -m pip install {mod}")
    if missing:
        print(f"\n  {BAD} install the missing packages and re-run.")
        return False
    return True


def db_check() -> bool:
    print(STEP.format("2/4 databases"))
    ok = True
    for db, label in ((COMPANY_DB, "company data"),
                      (EXECUTIVES_DB, "executives (CIA-C demo)"),
                      (AUDIT_DB, "hash-chained audit")):
        if db.exists():
            print(f"  {OK} {label}: {db.name}")
        else:
            ok = False
            print(f"  {BAD} {label} missing: {db}")
    if not ok:
        print(f"\n  {WARN} run:  python scripts/seed_company_data.py && "
              "python scripts/seed_users.py")
    else:
        n_users = _user_count()
        print(f"  {OK} users seeded: {n_users}"
              if n_users else
              f"  {WARN} no users yet - run: python scripts/seed_users.py")
    return ok


def _user_count() -> int:
    try:
        import sqlite3
        with sqlite3.connect(COMPANY_DB) as con:
            return int(con.execute(
                "SELECT COUNT(*) FROM users").fetchone()[0])
    except Exception:                          # noqa: BLE001 - setup aid only
        return 0


def llm_check_and_pick(assume_yes: bool, model_flag: str | None,
                       check_only: bool) -> bool:
    print(STEP.format("3/4 LLM backend check"))
    cfg = app_config()
    base = get_nested(cfg, "model.ollama_url", "http://localhost:11434")
    provider = get_nested(cfg, "model.provider", "auto")
    print(f"  provider: {provider}   ollama_url: {base}")

    env_url = os.environ.get("OLLAMA_URL")
    if env_url:
        base = env_url
    det = catalog.list_ollama_models(base)

    if not det["reachable"]:
        print(f"  {BAD} Ollama is NOT reachable at {base}")
        print(f"       ({det['error']})")
        print("  fix:   ollama serve            # or install: "
              "https://ollama.com/download")
        print("  then:  ollama pull qwen2.5:0.5b   (~400 MB, CPU-friendly)")
        print(f"  {WARN} until then the app runs on the VISIBLE mock "
              "backend (answers are clearly labelled, never fake-real).")
        return False

    models = det["models"]
    current = catalog.current_selection(cfg)
    rec = catalog.recommend(models)
    print(f"  {OK} Ollama up - {len(models)} model(s) available:\n")
    print(f"  {'#':>2}  {'model':<52} {'size':>8} {'class':>6} {'score':>5}")
    for i, m in enumerate(models, 1):
        star = ""
        if m["name"] == rec:
            star = "  <-- best fit for chat (recommended)"
        in_use = " (in use)" if m["name"] == current["ollama_model"] else ""
        print(f"  {i:>2}  {m['name'][:52]:<52} {m['size_human']:>8} "
              f"{m['param_class']:>6} {m['score']:>5}{star}{in_use}")
    print("\n  scores estimate chat suitability (params + family quality); "
          "the estimate is a heuristic - the human always confirms.")

    if check_only:
        print(f"\n  {OK} check-only: would select '{rec}'")
        return True

    choice: str | None = None
    if model_flag:
        wanted = model_flag.strip()
        if not any(m["name"] == wanted for m in models):
            print(f"\n  {BAD} '{wanted}' is not served by Ollama - "
                  "pick an id from the table above (ollama pull first "
                  "if missing).")
            return False
        choice = wanted
    else:
        try:
            raw = input(f"\n  select model [1-{len(models)}] "
                        f"(Enter = recommended: {rec}): ").strip()
        except EOFError:
            raw = ""
        if not raw:
            choice = rec
        elif raw.isdigit() and 1 <= int(raw) <= len(models):
            choice = models[int(raw) - 1]["name"]
        else:
            # free-text model id (e.g. pulled after the check started)
            if any(m["name"] == raw for m in models):
                choice = raw
            elif assume_yes or raw.lower() in ("y", "yes"):
                choice = rec
            else:
                print(f"  {BAD} '{raw}' is not in the catalog.")
                return False

    applied = catalog.apply_model_selection(choice)
    print(f"\n  {OK} selected model: {choice}")
    print(f"  {OK} written to: {applied['config']} "
          "(ollama_model + fast_model + reasoner_model, comments kept)")
    print("  the running API hot-reloads this on the next request "
          "(no restart); admins can also switch it live in the web UI "
          "under Administration -> AI models.")
    return True


def telegram_check() -> None:
    print(STEP.format("4/4 channels (optional)"))
    tg = get_nested(app_config(), "telegram", {}) or {}
    enabled = tg.get("enabled", False)
    token = bool(os.environ.get("TELEGRAM_BOT_TOKEN"))
    if enabled and token:
        print(f"  {OK} telegram bridge: enabled + bot token present")
        print("       run it with the whole stack in one window:")
        print("       bash /home/z/my-project/scripts/telegram_e2e.sh 120")
    elif enabled:
        print(f"  {WARN} telegram.enabled=true but TELEGRAM_BOT_TOKEN "
              "is not in the environment (bridge will refuse to start - "
              "fail closed by design)")
    else:
        print(f"  {OK} telegram bridge: disabled (set telegram.enabled: "
              "true + TELEGRAM_BOT_TOKEN to opt in)")


def main() -> int:
    ap = argparse.ArgumentParser(description="SecureLLM-Enterprise setup "
                                             "wizard")
    ap.add_argument("--check-only", action="store_true",
                    help="run all checks, change nothing")
    ap.add_argument("--model", metavar="ID",
                    help="select this ollama model id non-interactively")
    ap.add_argument("--yes", action="store_true",
                    help="accept the recommended model without prompting")
    args = ap.parse_args()

    print(__doc__.split('"""')[0].strip() if False else
          "SecureLLM-Enterprise setup wizard\n" + "-" * 34)
    ok = True
    ok = dep_check() and ok
    ok = db_check() and ok
    ok = llm_check_and_pick(args.yes, args.model, args.check_only) and ok
    telegram_check()

    print(STEP.format("summary"))
    print(f"  checks: {'ALL GREEN' if ok else 'SEE [!!] ITEMS ABOVE'}")
    print("  start the app:   uvicorn src.api.main:app --port 8000")
    print("  open the chat:   http://localhost:8000/   (redirects to "
          "/chat -> login)")
    print("  governance UI:   http://localhost:8000/dashboard (admin "
          "role only)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
