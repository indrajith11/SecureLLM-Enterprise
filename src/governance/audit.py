"""Layer 7: Audit logging (the "black box") - tamper-evident AND tamper-RESISTANT.

Every event (allow OR block, login OR query) is appended to:
  - db/audit.db  : SQLite, append-only usage pattern
  - logs/audit.jsonl : JSONL mirror for external SIEM shipping (rotated)

Each record carries prev_hash/hash forming a chain. RAG-04 remediation: the
stored value is no longer a bare SHA-256 of the record body (anyone who can
write the file could recompute the whole chain and pass verify()). It is now

    chain_hash = HMAC-SHA256(AUDIT_SIGN_KEY, sha256(canonical_body))

with the signing key NEVER stored in the database: AUDIT_HMAC_KEY env var,
falling back to a value derived from the JWT secret. An attacker with full
DB write access can still corrupt rows, but cannot forge a valid-looking
chain without the key - verify() detects it. (KMS/HSM anchoring and SIEM
ship-off remain the production hardening path; see docs/ROADMAP.md.)

RAG-05 remediation: verify_cached() recomputes the chain at most every
VERIFY_TTL_S seconds and serves the cached verdict to hot paths (/health,
/api/stats); GET /admin/audit/verify still forces a full walk. Appends are
no longer blocked behind long re-hashes.

RAG-07 remediation: configurable retention (audit.retention_days, default
180) with a purge job that preserves chain verifiability across deletions
by re-anchoring the genesis hash in audit_meta, plus size-based rotation of
the JSONL mirror (audit.jsonl -> .1 -> .2 -> .3).

Enhancement (per-user CIA enforcement): every record also carries the
action class (LOGIN / QUERY / BLOCKED / APPROVED / DENIED / RATE_LIMITED),
the acting username, the CIA pillar violated (C / I / A), the layer that
blocked and a human reason. The `audit_events` view exposes the schema used
in docs/database_schema.md.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

from src.common.paths import AUDIT_DB, LOGS_DIR, app_config, get_nested

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
    meta TEXT,
    prev_hash TEXT, hash TEXT
);
CREATE TABLE IF NOT EXISTS review_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, user_id TEXT, role TEXT, prompt TEXT,
    withheld_response TEXT, reason TEXT, status TEXT DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS audit_meta (
    key TEXT PRIMARY KEY, value TEXT
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

_LOCK = threading.RLock()
_VERIFY_TTL_S = 30.0
_JSONL_MAX_BYTES = 10 * 1024 * 1024      # 10 MB per mirror file
_JSONL_KEEP = 3                          # .1 .2 .3 retained

# canonical fields of the hash body (order-independent: sorted-keys JSON).
# Remediation note (deeper than RAG-04): the original chain hashed prompt
# metadata but NOT the model response or the retrieved context - an
# attacker with DB write access could silently edit the ANSWER text of any
# historical event. ai_response + retrieved_context are now chain-covered.
_BODY_FIELDS = ("ts", "user_id", "role", "prompt", "input_action",
                "output_action", "blocked_by", "latency_ms", "action",
                "cia_violation", "layer_blocked", "retrieved_context",
                "ai_response", "prev_hash")

_GENESIS = "0" * 64


def _canonical(rec: dict) -> str:
    return json.dumps(rec, sort_keys=True, ensure_ascii=False)


def _sign_key() -> bytes:
    """HMAC key: AUDIT_HMAC_KEY env, else derived from the JWT secret.
    Never persisted in (or near) the database it protects (RAG-04)."""
    env = os.environ.get("AUDIT_HMAC_KEY")
    if env:
        return env.encode()
    from src.governance.auth import _secret          # local import: no cycle
    return hashlib.sha256(b"securellm-audit-chain:" +
                          _secret().encode()).digest()


def _chain_hash(body: dict) -> str:
    body_hash = hashlib.sha256(_canonical(body).encode()).hexdigest()
    return hmac.new(_sign_key(), body_hash.encode(),
                    hashlib.sha256).hexdigest()


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
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts)")
        self._migrate()
        self.conn.commit()
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self._verify_cache: tuple[float, bool, int | None] = (0.0, True, None)
        self._ensure_sign_key_pinned()

    def _migrate(self) -> None:
        """Upgrade an older audit.db in place (CREATE IF NOT EXISTS keeps an
        existing table, so new columns are added by ALTER)."""
        have = {r[1] for r in self.conn.execute("PRAGMA table_info(audit)")}
        for col in ("action", "username", "cia_violation", "layer_blocked",
                    "reason", "meta"):
            if col not in have:
                self.conn.execute(
                    f"ALTER TABLE audit ADD COLUMN {col} TEXT")  # noqa: S608

    def _ensure_sign_key_pinned(self) -> None:
        """First boot pins the key fingerprint in audit_meta. If the key
        later changes, verification failure is EXPLICIT and explainable
        ('chain signed with a different key') instead of mysterious."""
        row = self.conn.execute(
            "SELECT value FROM audit_meta WHERE key='sign_key_fp'").fetchone()
        fp = hashlib.sha256(_sign_key()).hexdigest()[:16]
        if row is None:
            self.conn.execute(
                "INSERT INTO audit_meta (key, value) VALUES ('sign_key_fp',?)",
                (fp,))
            self.conn.commit()
        # (mismatch is reported by verify() as key_mismatch, not silently)

    # ---- genesis anchor (retention-aware chain verification) --------------
    def _genesis(self) -> str:
        row = self.conn.execute(
            "SELECT value FROM audit_meta WHERE key='genesis_hash'").fetchone()
        return row[0] if row else _GENESIS

    def _last_hash(self) -> str:
        row = self.conn.execute(
            "SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else self._genesis()

    def append(self, *, user_id: str, role: str, prompt: str,
               retrieved_context: str, ai_response: str,
               input_action: str, output_action: str,
               blocked_by: str, latency_ms: float,
               action: str = "QUERY", cia_violation: str | None = None,
               layer_blocked: str | None = None,
               reason: str | None = None,
               meta: dict | None = None) -> int:
        """meta (optional dict, e.g. the model-identity record of the answer:
        backend / model / intent / degraded) is stored as JSON and IS covered
        by the chain hash when present. Rows written before this column
        existed hash without it, so a populated pre-upgrade chain still
        verifies unchanged - and any later meta edit still breaks the walk
        (pre-deploy gate Step 7: model version tracking)."""
        with _LOCK:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            meta_rec = (json.dumps(meta, sort_keys=True, ensure_ascii=False)
                        if meta else "")
            prev = self._last_hash()
            body = {"ts": ts, "user_id": user_id, "role": role,
                    "prompt": prompt, "input_action": input_action,
                    "output_action": output_action, "blocked_by": blocked_by,
                    "latency_ms": latency_ms, "action": action,
                    "cia_violation": cia_violation or "",
                    "layer_blocked": layer_blocked or blocked_by or "",
                    "retrieved_context": retrieved_context,
                    "ai_response": ai_response,
                    "prev_hash": prev}
            if meta_rec:
                body["meta"] = meta_rec
            h = _chain_hash(body)
            cur = self.conn.execute(
                "INSERT INTO audit (ts,user_id,role,prompt,retrieved_context,"
                "ai_response,input_filter_action,output_filter_action,"
                "blocked_by,latency_ms,action,username,cia_violation,"
                "layer_blocked,reason,meta,prev_hash,hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ts, user_id, role, prompt, retrieved_context, ai_response,
                 input_action, output_action, blocked_by, latency_ms, action,
                 user_id, cia_violation, layer_blocked or blocked_by or "",
                 reason or "", meta_rec, prev, h))
            self.conn.commit()
            self._verify_cache = (0.0, True, None)   # head moved: re-verify
            self._jsonl_append({**body, "hash": h, "id": cur.lastrowid})
            return cur.lastrowid

    # ---- RAG-07: rotated JSONL mirror --------------------------------------
    def _jsonl_append(self, record: dict) -> None:
        path = LOGS_DIR / "audit.jsonl"
        if path.exists() and path.stat().st_size >= _JSONL_MAX_BYTES:
            for i in range(_JSONL_KEEP - 1, 0, -1):
                src = LOGS_DIR / f"audit.jsonl.{i}"
                dst = LOGS_DIR / f"audit.jsonl.{i + 1}"
                if src.exists():
                    os.replace(src, dst)
            os.replace(path, LOGS_DIR / "audit.jsonl.1")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(_canonical(record) + "\n")

    # ---- verification -------------------------------------------------------
    def verify(self) -> tuple[bool, int | None]:
        """Full walk of the chain (authoritative; used by
        /admin/audit/verify). HMAC key mismatch or any body/hash divergence
        fails closed."""
        with _LOCK:
            rows = self.conn.execute(
                "SELECT id, ts, user_id, role, prompt, input_filter_action, "
                "output_filter_action, blocked_by, latency_ms, action, "
                "cia_violation, layer_blocked, retrieved_context, "
                "ai_response, prev_hash, hash, meta "
                "FROM audit WHERE id > COALESCE("
                "(SELECT CAST(value AS INTEGER) FROM audit_meta "
                " WHERE key='purged_through_id'), 0) ORDER BY id"
            ).fetchall()
        prev = self._genesis()
        fp_expected = self.conn.execute(
            "SELECT value FROM audit_meta WHERE key='sign_key_fp'"
        ).fetchone()
        if fp_expected and fp_expected[0] != \
                hashlib.sha256(_sign_key()).hexdigest()[:16]:
            # key changed since the chain was pinned. An EMPTY chain adopts
            # the current key (nothing to protect yet); a populated chain
            # fails closed - a populated chain signed by another key is
            # exactly what tampering-with-the-key looks like.
            remaining = self.conn.execute(
                "SELECT COUNT(*) FROM audit WHERE id > COALESCE("
                "(SELECT CAST(value AS INTEGER) FROM audit_meta "
                " WHERE key='purged_through_id'), 0)").fetchone()[0]
            if remaining == 0:
                self.conn.execute(
                    "UPDATE audit_meta SET value=? WHERE key='sign_key_fp'",
                    (hashlib.sha256(_sign_key()).hexdigest()[:16],))
                self.conn.commit()
            else:
                return False, 0                 # key changed: fail closed
        for (rid, ts, uid, role, prompt, ia, oa, bb, lat, action, cia,
             layer_b, rc, ar, prev_h, h, meta_raw) in rows:
            if prev_h != prev:
                return False, rid
            body = {"ts": ts, "user_id": uid, "role": role, "prompt": prompt,
                    "input_action": ia, "output_action": oa, "blocked_by": bb,
                    "latency_ms": lat, "action": action,
                    "cia_violation": cia or "",
                    "layer_blocked": layer_b or "",
                    "retrieved_context": rc or "",
                    "ai_response": ar or "", "prev_hash": prev_h}
            if meta_raw:
                # conditional coverage: rows that carried meta were hashed
                # WITH it (append()); legacy rows hash exactly as before
                body["meta"] = meta_raw
            if not hmac.compare_digest(_chain_hash(body), h):
                return False, rid
            prev = h
        return True, None

    def verify_cached(self) -> tuple[bool, int | None]:
        """RAG-05: hot-path verification. Full recompute at most once per
        VERIFY_TTL_S; every other caller gets the cached verdict, so /health
        and /api/stats scrapes never block appends behind a full re-hash."""
        now = time.monotonic()
        with _LOCK:
            checked_at, ok, bad = self._verify_cache
            if now - checked_at < _VERIFY_TTL_S:
                return ok, bad
        ok, bad = self.verify()
        with _LOCK:
            self._verify_cache = (now, ok, bad)
        return ok, bad

    # ---- RAG-07: retention --------------------------------------------------
    def purge(self, retention_days: int | None = None) -> int:
        """Delete events older than the retention window WITHOUT breaking
        chain verifiability: the anchor (last purged hash + id) is stored in
        audit_meta and verify() treats it as the genesis. Returns the count
        of purged rows."""
        days = retention_days if retention_days is not None else int(
            get_nested(app_config(), "audit.retention_days", 180))
        if days <= 0:
            return 0
        cutoff = time.strftime(
            "%Y-%m-%dT%H:%M:%S%z", time.localtime(time.time() - days * 86400))
        with _LOCK:
            row = self.conn.execute(
                "SELECT id, hash FROM audit WHERE ts < ? "
                "ORDER BY id DESC LIMIT 1", (cutoff,)).fetchone()
            if not row:
                return 0
            anchor_id, anchor_hash = row
            cur = self.conn.execute(
                "DELETE FROM audit WHERE id <= ?", (anchor_id,))
            self.conn.execute(
                "INSERT INTO audit_meta (key, value) VALUES "
                "('genesis_hash', ?) ON CONFLICT(key) DO UPDATE SET "
                "value=excluded.value", (anchor_hash,))
            self.conn.execute(
                "INSERT INTO audit_meta (key, value) VALUES "
                "('purged_through_id', ?) ON CONFLICT(key) DO UPDATE SET "
                "value=excluded.value", (str(anchor_id),))
            self.conn.commit()
            self._verify_cache = (0.0, True, None)
            return cur.rowcount

    def start_maintenance(self, interval_hours: float = 6.0) -> None:
        """Background retention thread (RAG-07): purges on the interval so
        the log can never grow unbounded in a long-lived deployment."""

        def _loop():
            while True:
                time.sleep(interval_hours * 3600)
                try:
                    self.purge()
                except Exception:
                    pass

        t = threading.Thread(target=_loop, name="audit-retention",
                             daemon=True)
        t.start()

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
