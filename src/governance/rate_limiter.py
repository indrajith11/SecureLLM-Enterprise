"""Layer 2a: token-aware rate limiting (OWASP LLM10: Unbounded Consumption).

Sliding window per user with two budgets: request count and estimated tokens
(~4 chars/token). Exceeding either returns a bounded retry window instead of
letting one user exhaust model capacity for everyone (availability pillar).
"""
import threading
import time
from collections import defaultdict, deque


class SlidingWindowRateLimiter:
    def __init__(self, requests_per_minute: int = 20,
                 token_budget_per_minute: int = 6000):
        self.rpm = requests_per_minute
        self.tpm = token_budget_per_minute
        self._req: dict[str, deque] = defaultdict(deque)
        self._tok: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, user_id: str, est_tokens: int) -> tuple[bool, int, str]:
        """Returns (allowed, retry_after_seconds, reason)."""
        now = time.time()
        with self._lock:
            rq, tq = self._req[user_id], self._tok[user_id]
            while rq and now - rq[0] > 60:
                rq.popleft()
            while tq and now - tq[0][0] > 60:
                tq.popleft()
            if len(rq) >= self.rpm:
                return False, int(60 - (now - rq[0]) + 1), "request limit"
            spent = sum(t for _, t in tq)
            if spent + est_tokens > self.tpm:
                return False, int(60 - (now - tq[0][0]) + 1), "token budget"
            rq.append(now)
            tq.append((now, est_tokens))
            return True, 0, ""
