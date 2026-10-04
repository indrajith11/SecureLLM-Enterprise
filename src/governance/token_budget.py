"""Layer 2c: per-session token budget (OWASP LLM10 - KV-cache exhaustion).

The per-user per-minute limiter (rate_limiter.py) stops request FLOODS.
It does not stop one long-lived session from slowly eating unbounded
inference resources: a serving engine keeps conversation state in the
KV-cache, so the resource that must be bounded is TOTAL tokens per
session - input AND output. A single request is small; ten thousand of
them in one conversation is a memory-exhaustion attack (LLM10
"unbounded consumption", availability pillar, NIST AI RMF MEASURE 2.7).

TokenBudgetGuard tracks a rolling window of actual consumption per
session id and blocks requests that would push the window over budget.

Deliberate semantics (documented for the audit trail):
- key = JWT session id (a fresh login starts a fresh budget) - this
  mirrors how serving engines pin KV-cache blocks to a conversation;
- input tokens are recorded when a request actually reaches the model
  (a firewall deny burns zero tokens), output tokens are recorded as
  the stream is produced - a mid-stream revoked answer still consumed
  its tokens and still counts;
- token counts are ESTIMATED at the same chars/token ratio the L2 rate
  limiter uses (rate_limit.est_chars_per_token, default 4) so both
  guards share one consistent, tunable estimator. Ollama exposes exact
  prompt_eval_count/eval_count values - swapping the estimator for real
  provider usage is a drop-in future upgrade (see
  docs/architecture/LLM_INTERNALS.md), deliberately not wired tonight
  to keep the provider wire contract unchanged;
- the deny check is conservative: the REQUESTED input estimate is added
  to the window before comparing against the budget, so a request can
  never push a session past the cap.
"""
import threading
import time
from collections import defaultdict, deque


class TokenBudgetGuard:
    """Rolling-window token budget per session (thread-safe)."""

    def __init__(self, max_tokens: int = 20000, window_seconds: int = 600,
                 est_chars_per_token: int = 4):
        self.max_tokens = int(max_tokens)
        self.window_seconds = int(window_seconds)
        self.est_chars_per_token = max(1, int(est_chars_per_token))
        self._spent: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    # -- core accounting ----------------------------------------------------
    @staticmethod
    def _evict(q: deque, now: float, window: float) -> None:
        while q and now - q[0][0] > window:
            q.popleft()

    def check(self, key: str, est_in_tokens: int) -> tuple[bool, int, int, str]:
        """Would admitting this request stay inside the session budget?

        Returns (allowed, retry_after_seconds, spent_in_window, reason).
        The requested input is tentatively added to the window when
        allowed (the caller records actual output later via
        record_output())."""
        now = time.time()
        with self._lock:
            q = self._spent[key]
            self._evict(q, now, self.window_seconds)
            spent = sum(t for _, t in q)
            if spent + max(0, est_in_tokens) > self.max_tokens:
                retry = max(1, int(self.window_seconds - (now - q[0][0])) + 1) if q else 1
                return False, retry, spent, (
                    f"session token budget exhausted "
                    f"({spent}/{self.max_tokens} in the last "
                    f"{self.window_seconds}s)")
            q.append((now, max(0, est_in_tokens)))
            return True, 0, spent + max(0, est_in_tokens), ""

    def record(self, key: str, in_tokens: int = 0, out_tokens: int = 0) -> int:
        """Account one request's ACTUAL consumption. Callers pass the input
        DELTA (actual input minus the admission placeholder, so the window
        never double-counts) plus the output tokens. Returns the spend."""
        now = time.time()
        with self._lock:
            q = self._spent[key]
            self._evict(q, now, self.window_seconds)
            q.append((now, max(0, int(in_tokens))))
            q.append((now, max(0, int(out_tokens))))
            return sum(t for _, t in q)

    def record_output(self, key: str, out_tokens: int) -> int:
        """Account tokens actually produced by the model (streaming-safe:
        call per chunk or per response). Returns the window spend."""
        now = time.time()
        with self._lock:
            q = self._spent[key]
            self._evict(q, now, self.window_seconds)
            q.append((now, max(0, int(out_tokens))))
            return sum(t for _, t in q)

    def spent(self, key: str) -> int:
        now = time.time()
        with self._lock:
            q = self._spent.get(key)
            if not q:
                return 0
            self._evict(q, now, self.window_seconds)
            return sum(t for _, t in q)

    def est(self, text: str) -> int:
        """Estimate token count for a TEXT with the shared ratio."""
        return self.est_chars(len(text or ""))

    def est_chars(self, char_count: int) -> int:
        """Estimate token count from an already-computed CHAR COUNT
        (used when the caller has assembled prompts from parts)."""
        return max(1, int(char_count) // self.est_chars_per_token)

    # -- ops / test helpers ---------------------------------------------------
    def reset(self) -> None:
        with self._lock:
            self._spent.clear()
