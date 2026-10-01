"""Shared fixtures: app client, demo auth headers, poisoned-doc injection."""
import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.common.paths import COMPANY_DB, DOCS_DIR, VECTOR_INDEX_DIR
from src.rag.vector_store import VectorStore

PROBES = json.loads(
    (Path(__file__).parent / "probes" / "jailbreaks.json").read_text())["probes"]


def _ensure_seeded() -> None:
    """Guarantee the users table exists with all demo accounts (bcrypt).
    Idempotent + cheap: only hashes when accounts are missing. The schema
    migration (Wave 2.1: role_version / must_change_password) always runs
    so an existing runtime DB is upgraded in place."""
    from src.db.seed_users import DEMO_USERS, ensure_users_table, seed
    try:
        ensure_users_table()
        conn = sqlite3.connect(COMPANY_DB)
        n = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
            "AND name='users'").fetchone()[0]
        if n:
            n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        conn.close()
        if n < len(DEMO_USERS):
            seed()
    except sqlite3.Error:
        seed()


_ensure_seeded()


@pytest.fixture(autouse=True)
def _clean_governance_state():
    """Deterministic suite: every test starts with clean in-process
    governance state (rate window, sessions, lockout counters, revocation
    list, global chat gate). Without this, the module-global limiter makes
    results order-dependent once the suite grows."""
    from src.api import main as m
    from src.governance import auth
    m.limiter._req.clear()
    m.limiter._tok.clear()
    m.cia.sessions.reset()
    auth._fails.clear()
    auth._revoked.clear()
    m._USER_INFLIGHT.clear()      # Wave 3.2: per-user concurrency counters
    yield
    # also clear AFTER, so the final state never leaks into other sessions
    m.limiter._req.clear()
    m.limiter._tok.clear()
    m.cia.sessions.reset()
    auth._fails.clear()
    auth._revoked.clear()
    m._USER_INFLIGHT.clear()


def _reset_audit_chain_inplace() -> None:
    """Reset the LIVE canonical chain in place (same file, same connection):
    clearing rows + anchors re-pins the signing key on next verify. Never
    unlink the file - the canonical AuditChain holds an open connection."""
    import os
    from src.api.main import audit as _audit
    os.environ.pop("AUDIT_HMAC_KEY", None)
    with __import__("src.governance.audit", fromlist=["_LOCK"])._LOCK:
        _audit.conn.execute("DELETE FROM audit")
        _audit.conn.execute("DELETE FROM review_queue")
        _audit.conn.execute("DELETE FROM audit_meta")
        _audit.conn.commit()
    _audit._verify_cache = (0.0, True, None)


@pytest.fixture(scope="session")
def client():
    # hermetic audit state: start the session from a FRESH chain with the
    # canonical signing key, whatever earlier local runs did to db/audit.db
    _reset_audit_chain_inplace()

    # governance tests are functional tests: lift the rate budget so the
    # 60+ probes and RBAC tests are not 429-starved. The flood test
    # re-enables real limits locally.
    from src.api.main import limiter
    limiter.rpm, limiter.tpm = 10**6, 10**9
    with TestClient(app) as c:
        yield c
    # leave a pristine, valid audit chain behind for the demo
    _reset_audit_chain_inplace()


def login(c: TestClient, username: str, password: str) -> dict:
    r = c.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


@pytest.fixture(scope="session")
def alice(client):
    return login(client, "alice", "alice123")


@pytest.fixture(scope="session")
def hr(client):
    return login(client, "hr_hari", "hari123")


@pytest.fixture(scope="session")
def exec_user(client):
    return login(client, "ceo_meera", "meera123")


_POISON_DIR = Path(__file__).parent / "fixtures" / "poisoned_docs"


@pytest.fixture
def poisoned_docs():
    """Copy poison fixtures into tech_docs, re-index, yield, then restore."""
    backup_dir = VECTOR_INDEX_DIR.parent / "vector_index_backup"
    if backup_dir.exists():
        shutil.rmtree(backup_dir)
    shutil.copytree(VECTOR_INDEX_DIR, backup_dir)
    added = []
    for src in _POISON_DIR.glob("*.txt"):
        shutil.copy(src, DOCS_DIR / "tech_docs" / src.name)
        added.append(src.name)
    store = VectorStore()
    for ns in ("hr_docs", "tech_docs", "exec_docs"):
        for p in sorted((DOCS_DIR / ns).glob("*.txt")):
            store.add(ns, p.stem, p.read_text(encoding="utf-8"), {"title": p.stem})
    store.save(VECTOR_INDEX_DIR)
    import src.api.main as api_main
    from src.rag.vector_store import VectorStore as _VS
    fresh = _VS.load(VECTOR_INDEX_DIR)
    old_store = api_main.store
    api_main.store = fresh
    yield added
    api_main.store = old_store
    shutil.rmtree(VECTOR_INDEX_DIR)
    shutil.move(str(backup_dir), str(VECTOR_INDEX_DIR))
    for name in added:
        (DOCS_DIR / "tech_docs" / name).unlink()
