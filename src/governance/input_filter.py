"""Layer 2b: LLM input firewall (the "bouncer") - OWASP LLM01 mitigation.

Two detection stages, both cheap and explainable:

1. Pattern matching - regexes for known jailbreak families (instruction
   override, role-play/DAN, system-prompt extraction, destructive SQL,
   encoding smuggling). Encoded payloads are decoded (base64 / hex / ROT13)
   and re-scanned, so "encode it and it passes" does not work.

2. Semantic heuristic score - weighted cues (override verbs, role-play
   markers, fabricated authority, sensitive-data keywords, obfuscation).
   Not a neural classifier: it is deterministic, auditable, and swappable
   with a fine-tuned classifier later (documented in docs/Architecture.md).

A prompt is BLOCKED when a core pattern hits or the score crosses the
threshold; otherwise it flows to Layer 3 where access control - not the
filter - decides what data may exist in the context.
"""
import base64
import codecs
import re
from dataclasses import dataclass, field

CORE_PATTERNS: list[tuple[str, str]] = [
    ("instruction_override", r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|rules?|directions?|text|system)"),
    ("instruction_override", r"(disregard|forget|cancel|override|drop)\s+(all\s+)?(your\s+|the\s+|previous\s+|prior\s+|above\s+)?(instructions?|rules?|system\s+prompt|configuration|directions?|guardrails?)"),
    ("instruction_override", r"stop\s+following\s+(the\s+)?(system\s+)?(prompt|rules|instructions)"),
    ("instruction_override", r"new\s+instructions?\s*:"),
    ("instruction_override", r"you\s+must\s+now\s+(answer|comply|obey|reveal|show|output)"),
    ("roleplay_dan", r"\bDAN\b|do\s+anything\s+now|developer\s+mode|evil\s+assistant|vulnbot|unguarded\s+mode"),
    ("roleplay_dan", r"(you\s+are|act\s+as|become|pretend\s+(to\s+be\s+)?|roleplay\s+as)\s+(an?\s+)?(unfiltered|hacker|unrestricted|unethical|evil|all[- ]knowing|no[- ](restrictions|limits|rules))"),
    ("roleplay_dan", r"you\s+are\s+now\s+(unrestricted|unfiltered|admin|evil|free|admingpt)"),
    ("roleplay_dan", r"(pretend|roleplay|imagine)\s+you\s+are\s+(the\s+|a\s+)?(hr\s+database|leaked\s+payroll|unrestricted)"),
    ("roleplay_dan", r"simulate\s+(a\s+)?(fictional\s+)?ai\s+named"),
    ("roleplay_dan", r"(without|with\s+no)\s+(any\s+)?(restrictions|limits|filters|rules|guardrails)"),
    ("prompt_extraction", r"(print|show|reveal|output|repeat|quote|leak|expose|summarize|recite|restate)\s+(me\s+)?(your\s+)?(full\s+|exact\s+|raw\s+|initial\s+|complete\s+)?(system\s+prompt|meta[- ]?prompt|instructions?|initial\s+configuration|rules\s+you\s+were\s+given)"),
    ("prompt_extraction", r"(what|which)\s+(are|were)\s+your\s+(exact\s+|original\s+)?(instructions|rules|system\s+prompt)"),
    ("prompt_extraction", r"(what|which)\s+rules?\s+(are|were|do)\s+you\s+(given|have|follow|operate)"),
    ("prompt_extraction", r"your\s+(initial|original|full\s+|complete\s+)?(initial\s+|original\s+)?(configuration|setup|instructions|prompt)\b.*?(output|print|show|reveal|verbatim|word)"),
    ("prompt_extraction", r"repeat\s+the\s+text\s+above"),
    ("prompt_extraction", r"(print|output)\s+your\s+(instructions|prompt)\s+in\s+(base64|hex)"),
    ("destructive_sql", r"(drop\s+table|delete\s+from|truncate\s+table|alter\s+table|insert\s+into|update\s+\w+\s+set)"),
    ("destructive_sql", r"(run|execute|fire)\s+(this\s+|the\s+)?(sql\s+)?(query|command|statement)"),
    ("destructive_sql", r"union\s+select|'\s*;\s*--|;\s*--"),
    ("encoding_smuggle", r"(decode|execute)\s+(this|the\s+following|it)\s*:?\s*[A-Za-z0-9+/=]{16,}"),
    ("encoding_smuggle", r"(decode|follow)\s+this\s*(and\s+(follow|execute|do\s+it))?\s*:\s*[A-Za-z0-9+/=]{16,}"),
    ("encoding_smuggle", r"rot13\s*[:\-]"),
    ("encoding_smuggle", r"hex\s+(as\s+commands|commands?)"),
]

# (cue regex, weight) - summed; block when total >= threshold.
CUES: list[tuple[str, float]] = [
    (r"\b(ignore|bypass|override|disable|unlock|circumvent|evade|strip)\b", 1.6),
    (r"\b(reveal|expose|leak|dump|extract|exfiltrate|smuggle)\b", 1.6),
    (r"\b(unrestricted|unfiltered|uncensored|no\s+restrictions|no\s+limits|anything\s+goes)\b", 1.8),
    (r"\b(secret|confidential|classified|restricted|private)\b", 1.0),
    (r"\b(salary|salaries|payroll|bonus|bonuses|compensation)\b", 1.0),
    (r"\b(i\s+am\s+the|as\s+your|the\s+ceo\s+asked|i\s+have\s+authorization|i\s+am\s+authorized|board\s+has\s+approved|i\s+am\s+from\s+the\s+audit)\b", 2.0),
    (r"\b(base64|rot13|hex|cipher|encoded|spell\s+it\s+out|character\s+by\s+character|in\s+reverse)\b", 1.4),
    (r"\b(system\s+prompt|meta[- ]?prompt|initial\s+instructions)\b", 2.0),
    (r"\b(act\s+as|pretend|roleplay|you\s+are\s+now|from\s+now\s+on|new\s+persona)\b", 1.2),
    (r"\b(all\s+employees|every\s+employee|entire\s+table|all\s+rows|whole\s+company|across\s+(all|every)\s+departments?)\b", 1.2),
    (r"\b(dan|cybergod|developer\s+mode)\b", 2.2),
    (r"\b(what\s+is\s+the\s+ceo'?s|print\s+the\s+ceo'?s|ceo'?s\s+salary|ceo'?s\s+bonus)\b", 1.6),
]

_DECODABLE = re.compile(r"[A-Za-z0-9+/=]{24,}")
_HEXPAIRS = re.compile(r"\b(?:[0-9a-fA-F]{2}\s+){4,}[0-9a-fA-F]{2}\b")


@dataclass
class InputVerdict:
    action: str                      # allow | block
    score: float = 0.0
    categories: list[str] = field(default_factory=list)
    matched: list[str] = field(default_factory=list)

    @property
    def reason(self) -> str:
        cats = ", ".join(sorted(set(self.categories))) or "heuristic score"
        return f"matched={self.matched[:3]}" + (f" categories={cats}" if self.categories else f" score={self.score:.1f}")


def _decode_variants(prompt: str) -> list[str]:
    """Return decoded renderings of smuggled payloads, if any."""
    out = []
    m = _DECODABLE.search(prompt)
    if m and len(m.group()) % 4 == 0:
        try:
            out.append(base64.b64decode(m.group(), validate=True).decode("utf-8", "ignore"))
        except Exception:
            pass
    hexblob = _HEXPAIRS.search(prompt)
    if hexblob:
        try:
            out.append(bytes.fromhex(hexblob.group().replace(" ", "")).decode("utf-8", "ignore"))
        except Exception:
            pass
    if re.search(r"\brot13\b", prompt, re.I):
        out.append(codecs.decode(prompt, "rot13"))
    return [o for o in out if o]


def inspect(prompt: str, block_score: float = 6.0) -> InputVerdict:
    candidates = [prompt] + _decode_variants(prompt)
    decoded_present = len(candidates) > 1
    categories, matched = [], []
    score = 0.0
    for text in candidates:
        low = text.lower()
        for cat, pattern in CORE_PATTERNS:
            if re.search(pattern, low):
                categories.append(cat)
                matched.append(re.search(pattern, low).group()[:48])
        if text is not prompt:  # decoded payload alone is suspicious
            score += 2.0
        for cue, weight in CUES:
            if re.search(cue, low):
                score += weight
    if decoded_present:
        # A >=24-char base64/hex blob that decodes cleanly has no legitimate
        # business use in a chat question -> treat smuggling itself as the hit.
        categories.append("encoding_smuggle")
        matched.append("decodable payload in prompt")
    if categories or score >= block_score:
        return InputVerdict("block", round(score, 2), categories, matched)
    return InputVerdict("allow", round(score, 2), categories, matched)
