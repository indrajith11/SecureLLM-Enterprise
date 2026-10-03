#!/usr/bin/env python
"""Per-user authority demo - the SAME questions asked under DIFFERENT
logins, answered by the LIVE small model (Ollama) through the full
governance pipeline.

What it proves, one by one:
  1. Identity: every answer is enforced by the LOGGED-IN user's role,
     clearance and department (CIA triad) - not by a shared account.
  2. Routing: general questions go straight to the AI chat; company-data
     questions go through retrieval scoped to the user's role. Both are
     audited (meta.router, hash-chained audit row).
  3. Data read path: retrieval only sees namespaces the role owns
     (namespaces_searched) and only tables the role may select
     (table_catalog); employee_pii is structurally invisible.
  4. Differences you can SEE: the identical salary question is answered
     for an Executive and denied for a Tech_Engineer.

Usage:
    python scripts/demo_per_user_authority.py            # API on :8000
    python scripts/demo_per_user_authority.py --base URL # custom target

The script never mutates data; it is read-only and demo-safe.
"""
from __future__ import annotations

import argparse
import json
import sys

import httpx

# (username, password, label) - the seeded demo directory
USERS = [
    ("admin",      "Admin@123",  "Admin (L5)"),
    ("ceo",        "Ceo@123",    "Executive (L5)"),
    ("hr_manager", "HrM@123",    "HR_Manager (L4)"),
    ("tech_eng1",  "TechE@123",  "Tech_Engineer (L3)"),
]

# the EXACT SAME question shown under multiple authorities, plus the
# routing/PÉI-structural checks
MATRIX = [
    # identical question, DIFFERENT authority -> different verdict
    ("What is Arun Mehta's salary?", ["ceo", "hr_manager", "tech_eng1"]),
    # policy reading (the canonical benign HR question, v4.8.0 regression)
    ("What is the HR policy on remote work?", ["hr_manager", "tech_eng1"]),
    # broad listing
    ("Show me all employees", ["admin", "tech_eng1"]),
    # general knowledge -> direct AI answer (router=general)
    ("What is the capital of France?", ["tech_eng1"]),
    # PII structural blindness: even Admin cannot reach the PII table
    ("What is Arun Mehta's Aadhaar number?", ["admin"]),
    ("What is Priya Sharma's PAN?", ["admin"]),
]


def _login(c: httpx.Client, base: str, u: str, p: str) -> str | None:
    r = c.post(f"{base}/api/login", json={"username": u, "password": p},
               timeout=60)
    if r.status_code != 200:
        print(f"    login FAILED: {r.status_code} {r.text[:120]}")
        return None
    return r.json()["access_token"]


def _ask(c: httpx.Client, base: str, tok: str, q: str) -> dict:
    r = c.post(f"{base}/api/chat",
               headers={"Authorization": f"Bearer {tok}"},
               json={"message": q, "channel": "web"}, timeout=120)
    if r.status_code != 200:
        return {"error": f"{r.status_code} {r.text[:200]}"}
    return r.json()


def _fmt(d: dict) -> str:
    if d.get("error"):
        return f"HTTP {d['error']}"
    tag = []
    if d.get("blocked_by"):
        tag.append(f"DENIED@{d['blocked_by']}"
                   f"({d.get('meta', {}).get('denied_code', '')})")
    router = (d.get("meta") or {}).get("router", "company")
    tag.append(f"router={router}")
    m = d.get("meta") or {}
    if m.get("backend"):
        tag.append(f"backend={m['backend']}/{m.get('model', '')}")
    ans = (d.get("response") or "").strip().replace("\n", " ")
    return f"[{' | '.join(tag)}]\n    {ans[:400]}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    h = httpx.Client()
    try:
        health = h.get(f"{base}/health", timeout=10).json()
        print(f"== stack health: {json.dumps(health)}\n")
    except Exception as e:                     # noqa: BLE001
        print(f"FATAL: API not reachable at {base}: {e}")
        return 2

    tokens: dict[str, str] = {}
    print("== 1. logins (every user gets their OWN JWT) ==")
    for u, p, label in USERS:
        tok = _login(h, base, u, p)
        if tok:
            tokens[u] = tok
            print(f"    {label:<22} -> OK")
    print()

    print("== 2. same question, different authority ==")
    for q, who in MATRIX:
        print(f"  Q: {q}")
        for u in who:
            if u not in tokens:
                continue
            label = next(l for uu, _, l in USERS if uu == u)
            d = _ask(h, base, tokens[u], q)
            print(f"    {label:<22} {_fmt(d)}")
        print()

    print("== 3. audit trail (last entries for tech_eng1) ==")
    tok = tokens.get("tech_eng1")
    if tok:
        body = h.get(f"{base}/api/audit/me",
                     headers={"Authorization": f"Bearer {tok}"},
                     timeout=30).json()
        rows = body.get("events", []) if isinstance(body, dict) else body
        n_blocks = body.get("blocked_attempts", "?") \
            if isinstance(body, dict) else "?"
        print(f"    (chain-verified trail: {len(rows)} events shown, "
              f"blocked_attempts={n_blocks})")
        for row in rows[-4:]:
            meta = {}
            try:
                meta = json.loads(row.get("meta") or "{}")
            except json.JSONDecodeError:
                pass
            print(f"    {str(row.get('ts', ''))[:19]} "
                  f"{str(row.get('action', '')):<14}"
                  f" router={meta.get('router', '-'):<8}"
                  f" backend={meta.get('backend', '-'):<7}"
                  f" blocked_by={row.get('blocked_by') or '-'}")
    print("\n== demo complete: every verdict above came from the logged-in")
    print("   user's own role/clearance through the same L1-L7 pipeline ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
