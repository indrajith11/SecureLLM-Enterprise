"""Layer 7: Audit logging (the "black box") - tamper-evident by construction.

Every event (allow OR block, login OR query) is appended to:
  - db/audit.db  : SQLite, append-only usage pattern
  - logs/audit.jsonl : JSONL mirror for external SIEM shipping

Each record carries prev_hash/hash forming a SHA-256 hash chain - the same
tamper-evidence idea as a blockchain ledger, but verifiable in one call
(GET /admin/audit/verify). Maps to ISO 27001 A.8.16 (monitoring activities)
and supports CERT-In's incident-reporting duty with an evidence trail.

Enhancement (per-user CIA enforcement): every record now also carries the
action class (LOGIN / QUERY / BLOCKED / APPROVED / DENIED / RATE_LIMITED),
the acting username, the CIA pillar violated (C / I / A or NULL), the
layer that blocked (L2 / L3.5 / L6 / CIA-C / CIA-I / CIA-A) and a human
reason. The `audit_events` view exposes the schema under the names used in
docs/database_schema.md.
"""
import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

from src.common.paths import AUDIT_DB, LOGS_DIR

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, user_id TEXT, role TEXT, prompt TEXT,
    retrieved_context TEXT, ai_response TEXT,
    input_filter_action TEXT, output_filter_action TEXT,
    blocked_by TEXT, latency_ms REAL,
    action TEXT DEFAULT 'QUERY',
    username TEXT,
    cia_violation TEXT,
    layer_blocked TEXT,
    reason TEXT,
    prev_hash TEXT, hash TEXT
);
CREATE TABLE IF NOT EXISTS review_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, user_id TEXT, role TEXT, prompt TEXT,
    withheld_response TEXT, reason TEXT, status TEXT DEFAULT 'open'
);
CREATE VIEW IF NOT EXISTS audit_events AS
    SELECT id AS event_id,
           ts AS timestamp,
           user_id,
           username,
           role,
           action,
           prompt AS query_text,
           ai_response AS response_text,
           cia_violation,
           layer_blocked,
           reason,
           input_filter_action,
           output_filter_action,
           latency_ms,
           prev_hash,
           hash
    FROM audit;
"""

_LOCK = threading.Lock()

# canonical fields of the hash body (order-independent: sorted-keys JSON)
_BODY_FIELDS = ("ts", "user_id", "role", "prompt", "input_action",
                "output_action", "blocked_by", "latency_ms", "action",
                "cia_violation", "layer_blocked", "prev_hash")


def _canonical(rec: dict) -> str:
    return json.dumps(rec, sort_keys=True, ensure_ascii=False)


class AuditChain:
    def __init__(self):
        AUDIT_DB.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(AUDIT_DB, check_same_thread=False)
        # S8 speed: WAL journaling + hot-path indexes (per-user trail reads
        # and pending-action polling no longer full-scan under load)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(_SCHEMA)
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_user_ts ON audit(user_id, ts)")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action)")
        self._migrate()
        self.conn.commit()
        LOGS_DIR.mkdir(parents=True, exist_ok=True)

    def _migrate(self) -> None:
        """Upgrade an older audit.db in place (CREATE IF NOT EXISTS keeps an
        existing table, so new columns are added by ALTER)."""
        have = {r[1] for r in self.conn.execute("PRAGMA table_info(audit)")}
        for col in ("action", "username", "cia_violation", "layer_blocked",
                    "reason"):
            if col not in have:
                self.conn.execute(
                    f"ALTER TABLE audit ADD COLUMN {col} TEXT")  # noqa: S608

    def _last_hash(self) -> str:
        row = self.conn.execute(
            "SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else "0" * 64

    def append(self, *, user_id: str, role: str, prompt: str,
               retrieved_context: str, ai_response: str,
               input_action: str, output_action: str,
               blocked_by: str, latency_ms: float,
               action: str = "QUERY", cia_violation: str | None = None,
               layer_blocked: str | None = None,
               reason: str | None = None) -> int:
        with _LOCK:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            prev = self._last_hash()
            body = {"ts": ts, "user_id": user_id, "role": role,
                    "prompt": prompt, "input_action": input_action,
                    "output_action": output_action, "blocked_by": blocked_by,
                    "latency_ms": latency_ms, "action": action,
                    "cia_violation": cia_violation or "",
                    "layer_blocked": layer_blocked or blocked_by or "",
                    "prev_hash": prev}
            h = hashlib.sha256(_canonical(body).encode()).hexdigest()
            cur = self.conn.execute(
                "INSERT INTO audit (ts,user_id,role,prompt,retrieved_context,"
                "ai_response,input_filter_action,output_filter_action,"
                "blocked_by,latency_ms,action,username,cia_violation,"
                "layer_blocked,reason,prev_hash,hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ts, user_id, role, prompt, retrieved_context, ai_response,
                 input_action, output_action, blocked_by, latency_ms, action,
                 user_id, cia_violation, layer_blocked or blocked_by or "",
                 reason or "", prev, h))
            self.conn.commit()
            with open(LOGS_DIR / "audit.jsonl", "a", encoding="utf-8") as fh:
                fh.write(_canonical({**body, "hash": h, "id": cur.lastrowid}) + "\n")
            return cur.lastrowid

    def verify(self) -> tuple[bool, int | None]:
        """Walk the chain; return (ok, first_bad_id)."""
        with _LOCK:
            rows = self.conn.execute(
                "SELECT id, ts, user_id, role, prompt, input_filter_action, "
                "output_filter_action, blocked_by, latency_ms, action, "
                "cia_violation, layer_blocked, prev_hash, hash "
                "FROM audit ORDER BY id").fetchall()
        prev = "0" * 64
        for (rid, ts, uid, role, prompt, ia, oa, bb, lat, action, cia,
             layer_b, prev_h, h) in rows:
            if prev_h != prev:
                return False, rid
            body = {"ts": ts, "user_id": uid, "role": role, "prompt": prompt,
                    "input_action": ia, "output_action": oa, "blocked_by": bb,
                    "latency_ms": lat, "action": action,
                    "cia_violation": cia or "",
                    "layer_blocked": layer_b or "", "prev_hash": prev_h}
            if hashlib.sha256(_canonical(body).encode()).hexdigest() != h:
                return False, rid
            prev = h
        return True, None

    def recent(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, ts, user_id, role, input_filter_action, "
            "output_filter_action, blocked_by, latency_ms, action, "
            "cia_violation, layer_blocked, reason FROM audit "
            "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        keys = ["id", "ts", "user_id", "role", "input_action",
                "output_action", "blocked_by", "latency_ms", "action",
                "cia_violation", "layer_blocked", "reason"]
        return [dict(zip(keys, r)) for r in rows]

    # ---- per-user audit trail (GET /api/audit/me) ---------------------
    def for_user(self, username: str, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT event_id, timestamp, action, query_text, response_text, "
            "cia_violation, layer_blocked, reason FROM audit_events "
            "WHERE username = ? ORDER BY event_id DESC LIMIT ?",
            (username, limit)).fetchall()
        keys = ["event_id", "timestamp", "action", "query", "response",
                "cia_violation", "layer_blocked", "reason"]
        return [dict(zip(keys, r)) for r in rows]

    def blocked_for_user(self, username: str, limit: int = 25) -> list[dict]:
        rows = self.conn.execute(
            "SELECT event_id, timestamp, query_text, cia_violation, "
            "layer_blocked, reason FROM audit_events "
            "WHERE username = ? AND action IN ('BLOCKED','DENIED',"
            "'RATE_LIMITED') ORDER BY event_id DESC LIMIT ?",
            (username, limit)).fetchall()
        keys = ["event_id", "timestamp", "query", "cia_violation",
                "layer_blocked", "reason"]
        return [dict(zip(keys, r)) for r in rows]

    def stats(self) -> dict:
        """System-wide counters for the Admin dashboard."""
        q = ("SELECT action, COUNT(*) FROM audit GROUP BY action")
        by_action = dict(self.conn.execute(q).fetchall())
        q = ("SELECT COALESCE(cia_violation,'-'), COUNT(*) FROM audit "
             "WHERE cia_violation IS NOT NULL AND cia_violation != '' "
             "GROUP BY cia_violation")
        by_cia = dict(self.conn.execute(q).fetchall())
        total = self.conn.execute("SELECT COUNT(*) FROM audit")\
            .fetchone()[0]
        users = self.conn.execute(
            "SELECT COUNT(DISTINCT username) FROM audit").fetchone()[0]
        return {"total_events": total, "distinct_users": users,
                "by_action": by_action, "by_cia_violation": by_cia}

    # ---- Layer 6.5: human-in-the-loop review queue -------------------
    def flag_for_review(self, *, user_id: str, role: str, prompt: str,
                        withheld: str, reason: str) -> int:
        with _LOCK:
            cur = self.conn.execute(
                "INSERT INTO review_queue (ts,user_id,role,prompt,"
                "withheld_response,reason) VALUES (?,?,?,?,?,?)",
                (time.strftime("%Y-%m-%dT%H:%M:%S%z"), user_id, role,
                 prompt, withheld, reason))
            self.conn.commit()
            return cur.lastrowid

    def review_list(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, ts, user_id, role, prompt, reason, status "
            "FROM review_queue WHERE status='open' ORDER BY id DESC").fetchall()
        return [dict(zip(["id", "ts", "user_id", "role", "prompt",
                          "reason", "status"], r))
                for r in rows]

    def review_resolve(self, item_id: int, release: bool) -> str | None:
        with _LOCK:
            row = self.conn.execute(
                "SELECT withheld_response, status FROM review_queue WHERE id=?",
                (item_id,)).fetchone()
            if not row or row[1] != "open":
                return None
            self.conn.execute(
                "UPDATE review_queue SET status=? WHERE id=?",
                ("released" if release else "rejected", item_id))
            self.conn.commit()
            return row[0] if release else None
