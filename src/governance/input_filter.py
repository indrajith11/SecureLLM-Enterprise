"""Layer 2b: LLM input firewall (the "bouncer") - OWASP LLM01 mitigation.

RULESET v2 - designed like a security engineer's WAF ruleset:

Stage 0  NORMALISATION  - NFKC fold, zero-width/bidi char removal, homoglyph
          folding (Cyrillic/Greek look-alikes -> Latin), whitespace collapse.
          Everything downstream matches on the normalised text, so
          "\u0456gnore" (Cyrillic i) or "ig\u200bnore" no longer evade.
Stage 1  PATTERN MATCH  - precompiled regexes for known jailbreak families
          (instruction override, DAN/roleplay, prompt extraction, destructive
          SQL, encoding smuggling, delimiter injection, tool/agent abuse,
          prompt extraction via translation/reformat asks). Encoded payloads
          (base64 / hex / ROT13) are decoded and the DECODED text re-scanned.
Stage 2  PAYLOAD-SPLIT CHECK - all non-alphanumerics are stripped and the
          compacted stream is re-scanned, defeating "I g n o r e  all
          previous instructions" style splitting.
Stage 3  SEMANTIC HEURISTIC - weighted cues summed; block at threshold.

All patterns are PRECOMPILED at import (latency) and every family is
counted in Prometheus via the caller. Deterministic and auditable by
design; the swap to a fine-tuned classifier is documented in
docs/Architecture.md. RULESET_VERSION is surfaced in /health so a deployed
ruleset can be pinned and audited.
"""
import base64
import codecs
import re
import unicodedata
from dataclasses import dataclass, field

RULESET_VERSION = "2.0"

# ---------------------------------------------------------------- stage 0
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"
                                "\u202a\u202b\u202c\u202d\u202e"), None)
_HOMOGLYPHS = {
    # Cyrillic look-alikes
    0x0430: "a", 0x0435: "e", 0x043e: "o", 0x0440: "p", 0x0441: "c",
    0x0443: "y", 0x0445: "x", 0x0456: "i", 0x0455: "s", 0x0463: "e",
    0x0438: "u", 0x0458: "j", 0x0452: "d", 0x0491: "g",
    # Greek look-alikes
    0x03bf: "o", 0x03b1: "a", 0x03b5: "e", 0x03c1: "p", 0x03c2: "c",
    0x03c5: "y", 0x03c7: "x", 0x03b9: "i", 0x03c3: "s",
}
_FOLD = str.maketrans(_HOMOGLYPHS)
_MULTI_SPACE = re.compile(r"\s+")


def normalize(text: str) -> str:
    """NFKC -> strip zero-width/bidi -> fold homoglyphs -> lowercase."""
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(_ZERO_WIDTH)
    t = t.translate(_FOLD)
    return _MULTI_SPACE.sub(" ", t).lower().strip()


# ---------------------------------------------------------------- stage 1
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
    ("prompt_extraction", r"(translate|rephrase|reword|rewrite|summarize)\s+(your\s+)?(system\s+)?(prompt|instructions|rules)\b"),
    ("destructive_sql", r"(drop\s+table|delete\s+from|truncate\s+table|alter\s+table|insert\s+into|update\s+\w+\s+set)"),
    ("destructive_sql", r"(run|execute|fire)\s+(this\s+|the\s+)?(sql\s+)?(query|command|statement)"),
    ("destructive_sql", r"union\s+select|'\s*;\s*--|;\s*--"),
    ("encoding_smuggle", r"(decode|execute)\s+(this|the\s+following|it)\s*:?\s*[A-Za-z0-9+/=]{16,}"),
    ("encoding_smuggle", r"(decode|follow)\s+this\s*(and\s+(follow|execute|do\s+it))?\s*:\s*[A-Za-z0-9+/=]{16,}"),
    ("encoding_smuggle", r"rot13\s*[:\-]"),
    ("encoding_smuggle", r"hex\s+(as\s+commands|commands?)"),
    # v2 families -------------------------------------------------------
    ("delimiter_injection", r"(#{2,}|\*{2,}|={2,}|---+)\s*(system|assistant|developer|instructions?)\s*:"),
    ("delimiter_injection", r"\[system\]|\(system\)|<\|?(system|im_start|im_end|endoftext)\|?>|</?s>|\[inst\]"),
    ("delimiter_injection", r"(begin|start)\s+(new\s+)?(system\s+)?(message|turn|prompt)\s*[:\n]"),
    ("tool_abuse", r"(call|invoke|use|run)\s+(the\s+)?(admin|executive|exec|root|sudo|internal|hidden)\s+(tool|function|api|command|endpoint)"),
    ("tool_abuse", r"(use|invoke)\s+(your\s+)?(tools?|functions?|plugins?)\s+(to|and)\s+(bypass|skip|ignore|disable)"),
    ("tool_abuse", r"(grant|give|make)\s+(me|us|\w+)\s+(admin|executive|root|approver|elevated)"),
    ("privilege_escalation", r"(elevate|escalate)\s+(my|the)?\s*.{0,15}(privileges?|permissions?|clearance|role|access)"),
    ("privilege_escalation", r"(approve|confirm)\s+(my|the)\s+own\b"),
]

# v2: payload-splitting - compacted (punctuation/space-stripped) forms
SPLIT_PATTERNS: list[re.Pattern] = [
    re.compile(p) for p in (
        r"ignoreall(?:previous|prior|the|your)?instructions?",
        r"disregardall(?:previous|prior|the)?(?:rules|instructions)",
        r"printyoursystemprompt",
        r"reveal(?:your)?systemprompt",
        r"ignorealloftheabove",
        r"yourenowunrestricted",
        r"ceasetofollow(?:all)?(?:previous)?instructions",
    )
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
    # v2 cues ------------------------------------------------------------
    (r"\b(grandmother|grandma|deathbed|last\s+wish|dying)\b", 1.6),
    (r"\b(api\s+keys?|access\s+key|secret\s+key|passwords?|credentials?)\b", 1.6),
    (r"\b(jwt|token|bearer)\b", 1.0),
]

_DECODABLE = re.compile(r"[A-Za-z0-9+/=]{24,}")
_HEXPAIRS = re.compile(r"\b(?:[0-9a-fA-F]{2}\s+){4,}[0-9a-fA-F]{2}\b")
_ROT13 = re.compile(r"\brot13\b", re.I)

# v2: precompiled (latency) - built once at import
_COMPILED = [(cat, re.compile(p, re.I)) for cat, p in CORE_PATTERNS]
_COMPACT_STRIP = re.compile(r"[^a-z0-9]+")


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
    if _ROT13.search(prompt):
        out.append(codecs.decode(prompt, "rot13"))
    return [o for o in out if o]


def inspect(prompt: str, block_score: float = 6.0) -> InputVerdict:
    candidates = [normalize(prompt)] + [normalize(v)
                                        for v in _decode_variants(prompt)]
    decoded_present = len(candidates) > 1
    categories, matched = [], []
    score = 0.0
    for text in candidates:
        for cat, pattern in _COMPILED:
            m = pattern.search(text)
            if m:
                categories.append(cat)
                matched.append(m.group()[:48])
        if text is not candidates[0]:  # decoded payload alone is suspicious
            score += 2.0
        for cue, weight in CUES:
            if re.search(cue, text):
                score += weight
    # v2 stage 2: compacted stream defeats payload splitting
    compact = _COMPACT_STRIP.sub("", candidates[0])
    for pattern in SPLIT_PATTERNS:
        m = pattern.search(compact)
        if m:
            categories.append("payload_splitting")
            matched.append(("split:" + m.group())[:48])
            break
    if decoded_present:
        # A >=24-char base64/hex blob that decodes cleanly has no legitimate
        # business use in a chat question -> treat smuggling itself as the hit.
        categories.append("encoding_smuggle")
        matched.append("decodable payload in prompt")
    if categories or score >= block_score:
        return InputVerdict("block", round(score, 2), categories, matched)
    return InputVerdict("allow", round(score, 2), categories, matched)
