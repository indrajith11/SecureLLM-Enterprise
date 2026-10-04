"""Layer 6s: real-time streaming DLP (OWASP LLM02/LLM10, SSE pipelines).

Batch output governance (output_filter.check) scans the FULL response
after generation finishes - correct for JSON /api/chat, but a streaming
client has already rendered every 'delta' event by the time a batch scan
fires. v5.0.0 (CHAT-02) therefore scans per completed sentence before
flushing it. This module extracts and hardens that logic into one
testable class and adds the window that was missing:

1. Sentence flush (unchanged semantics): each completed sentence is
   hard-checked (canary / system-prompt mark / injection residue /
   credential shapes / destructive-execution confirmation) and
   shape-redacted (money / email / phone) BEFORE it is emitted - a user
   never watches un-redacted PII render.

2. Forced scan window (v5.1.0, the upgrade): a model that emits a long
   run with NO sentence punctuation used to leave everything in the
   unflushed buffer - unscanned, unbounded in memory, and only caught by
   the final batch check at stream end. Now:
     - past scan_window_chars the whole pending buffer is hard-scanned
       in place (detection latency is bounded; a canary buried in a
       punctuation-free stream aborts the stream within the window);
     - past flush_cap_chars the buffer is force-flushed (hard-check +
       redact) with tail_keep_chars held back, bounding server memory
       for a runaway generation (OWASP LLM10).

3. Known boundary trade-off (documented, not hidden): a sensitive shape
   SPLIT across a force-flush boundary (needs > scan_window_chars of
   punctuation-free text ending mid-shape) can render as a fragment
   until the stream ends. The authoritative full Layer 6 check
   (faithfulness + cross-boundary shapes) still runs on the complete
   accumulated text in main.py, and the client renders the 'final'
   (or 'revoked') event as the truth - so nothing sensitive SURVIVES
   the stream; at worst a fragment is visible for the remaining stream
   duration. Closing that last window would require holding unbounded
   overlap buffers (the exact memory cost this layer bounds) - the
   trade-off is deliberate and audited.

4. Volume accounting: every chunk the model produced is counted
   (counted_chars) so the session token budget (token_budget.py) can
   charge output tokens even when the stream is later revoked - revoked
   answers still consumed KV-cache and compute (OWASP LLM10).
"""
import re

from src.governance import output_filter

# Sentence boundary: end punctuation + whitespace, or a newline.
SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+|\n")


class StreamingDLP:
    """Incremental output governance for one streamed response."""

    def __init__(self, role: str, self_scoped: bool = False,
                 scan_window_chars: int = 400,
                 flush_cap_chars: int = 2000,
                 tail_keep_chars: int = 64):
        if not 0 < tail_keep_chars < flush_cap_chars:
            tail_keep_chars = max(1, flush_cap_chars // 8)
        self.role = role
        self.self_scoped = self_scoped
        self.scan_window = max(1, int(scan_window_chars))
        self.flush_cap = max(self.scan_window + 1, int(flush_cap_chars))
        self.tail_keep = int(tail_keep_chars)
        self.pending = ""             # unflushed model output (never trusted)
        self.emitted: list[str] = []  # flushed (already governed) chunks
        self.counted_chars = 0        # RAW model volume seen (budget input)
        self.redactions: list[str] = []
        self.aborted = False
        self.abort_reasons: list[str] = []

    # -- internals -----------------------------------------------------------
    def _scan_and_emit(self, text: str) -> str | None:
        """Hard-check + redact one unit of text. Returns the safe text to
        emit, or None when a hard leak indicator aborts the stream."""
        hard = output_filter.hard_reasons(text, self.role)
        if hard:
            self.aborted = True
            self.abort_reasons = hard
            return None
        red = output_filter.redact(text, self.role,
                                   self_scoped=self.self_scoped)
        if red.redactions:
            self.redactions.extend(red.redactions)
        return red.text

    # -- public API -----------------------------------------------------------
    def feed(self, piece: str) -> list[str]:
        """Consume one raw model chunk; return the SAFE chunks to emit.

        After a hard abort (.aborted is True) every further feed() is a
        no-op - the caller must stop the stream and read
        .abort_reasons."""
        if self.aborted or not piece:
            return []
        self.pending += piece
        self.counted_chars += len(piece)
        out: list[str] = []

        # 1) flush every completed sentence after governing it
        while True:
            m = SENTENCE_BOUNDARY.search(self.pending)
            if not m:
                break
            sentence, self.pending = (self.pending[:m.end()],
                                      self.pending[m.end():])
            chunk = self._scan_and_emit(sentence)
            if chunk is None:
                return out
            if chunk:
                self.emitted.append(chunk)
                out.append(chunk)

        # 2) forced scan window: bound DETECTION latency for hard leak
        #    indicators hiding in a punctuation-free stream
        if len(self.pending) > self.scan_window:
            hard = output_filter.hard_reasons(self.pending, self.role)
            if hard:
                self.aborted = True
                self.abort_reasons = hard
                return out

        # 3) flush cap: bound server memory for a runaway generation
        #    (tail held back so a shape never straddles the boundary)
        if len(self.pending) > self.flush_cap:
            forced, self.pending = (self.pending[:-self.tail_keep],
                                    self.pending[-self.tail_keep:])
            chunk = self._scan_and_emit(forced)
            if chunk is None:
                return out
            if chunk:
                self.emitted.append(chunk)
                out.append(chunk)
        return out

    @property
    def emitted_text(self) -> str:
        return "".join(self.emitted)
