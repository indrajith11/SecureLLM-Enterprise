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
    Idempotent + cheap: only hashes when accounts are missing."""
    from src.db.seed_users import DEMO_USERS, seed
    try:
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


@pytest.fixture(scope="session")
def client():
    # governance tests are functional tests: lift the rate budget so the
    # 60+ probes and RBAC tests are not 429-starved. The flood test
    # re-enables real limits locally.
    from src.api.main import limiter
    limiter.rpm, limiter.tpm = 10**6, 10**9
    with TestClient(app) as c:
        yield c
    # leave a pristine, valid audit chain behind for the demo
    from src.common.paths import AUDIT_DB, LOGS_DIR
    from src.governance.audit import AuditChain
    AUDIT_DB.unlink(missing_ok=True)
    (LOGS_DIR / "audit.jsonl").unlink(missing_ok=True)
    AuditChain()


def login(c: TestClient, username: str, password: str) -> dict:
    r = c.post("/token", json={"username": username, "password": password})
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
