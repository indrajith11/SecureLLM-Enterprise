"""Layer 6: Output Governance (the "auditor") - last line of defence.

Three independent checks on EVERY model response before it reaches the user:

1. Role-aware DLP (OWASP LLM02): sensitive shapes are blocked per role -
   salary figures / emails / phones / bonuses for Tech staff, bonuses for
   HR, card numbers + system-prompt canary for everyone.
2. Canary check: the Layer 5 system prompt embeds the canary string
   CANARY-7f3a. If it appears in an output, the model leaked its
   instructions -> block (classic canary-token technique).
3. Faithfulness / hallucination check (OWASP LLM09: Misinformation):
   sensitive-shaped numbers in the output must exist in the retrieved
   context. A figure the context never contained is a hallucination or an
   injected leak -> block.
4. Indirect-injection residue check (OWASP LLM01, RAG poisoning):
   retrieved documents can carry attacker instructions ("SYSTEM OVERRIDE",
   "IGNORE ALL PREVIOUS RULES", "I HAVE BEEN HACKED"). A policy answer
   must NEVER echo such markers - if it does, the model obeyed retrieved
   content instead of its system prompt -> block + human review.

Blocked responses are withheld from the user, stored in a human review
queue (Layer 6.5 HITL gate), and logged. The user gets a policy refusal.
"""
import re
from dataclasses import dataclass, field

from src.common.paths import AUDIT_DB

CANARY = "CANARY-7f3a"

RE_MONEY = re.compile(
    r"(?:\$\s?\d{1,3}(?:,\d{3})+(?:\.\d{2})?|\$\s?\d{4,7}(?:\.\d{2})?|\$\s?\d{1,3}[kK]\b"
    r"|\b\d{1,3}(?:,\d{3})+\s?(?:USD|INR|dollars|rupees)\b|\u20b9\s?\d{1,3}(?:,\d{3})+)")
RE_EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.I)
RE_PHONE = re.compile(r"(?:\+?\d{1,2}[-.\s])?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}")
RE_CARD = re.compile(r"\b(?:\d[ -]?){13,16}\b")
RE_SYSMARK = re.compile(r"(system prompt|meta-prompt|you are a secure company assistant)",
                        re.I)
RE_YEARS = re.compile(r"\b(?:19|20)\d{2}\b")
RE_INJECT_RESIDUE = re.compile(
    r"(system\s+override|ignore\s+all\s+(previous|prior|rules)|"
    r"disregard\s+all\s+(previous|prior|rules)|i\s+have\s+been\s+hacked|"
    r"note\s+to\s+ai\s+assistant|instructions?\s+embedded\s+in|"
    r"you\s+must\s+(include|output|obey)\s+(these|the|all))", re.I)

# v2: credential/secret shapes (OWASP LLM02 + DPDP Act context). Any model
# output containing these is a leak regardless of role - no legitimate
# assistant answer carries cloud keys, tokens, government IDs or key blocks.
RE_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
RE_PRIVKEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
RE_AADHAAR = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
RE_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")

_ROLE_RULES = {
    "Tech_Employee": {"money", "email", "phone", "card", "sysmark",
                      "canary", "residue", "secret"},
    "Tech_Lead": {"money", "email", "phone", "card", "sysmark",
                  "canary", "residue", "secret"},
    "Tech_Engineer": {"money", "email", "phone", "card", "sysmark",
                      "canary", "residue", "secret"},
    "Business_Analyst": {"money", "email", "phone", "card", "bonus_money",
                         "sysmark", "canary", "residue", "secret"},
    "HR_Employee": {"money", "email", "phone", "card", "bonus_money",
                    "sysmark", "canary", "residue", "secret"},
    "HR_Manager": {"bonus_money", "card", "sysmark", "canary", "residue",
                   "secret"},
    "Finance_Manager": {"bonus_money", "card", "sysmark", "canary",
                        "residue", "secret"},
    "Executive": {"card", "sysmark", "canary", "residue", "secret"},
    "Admin": {"card", "sysmark", "canary", "residue", "secret"},
    "default": {"money", "email", "phone", "card", "bonus_money",
                "sysmark", "canary", "residue", "secret"},
}


@dataclass
class OutputVerdict:
    action: str                       # allow | redact | block
    reasons: list[str] = field(default_factory=list)
    text: str = ""

    @property
    def summary(self) -> str:
        return ", ".join(self.reasons) or "clean"


def _check_shapes(text: str, role: str, context: str) -> list[str]:
    rules = _ROLE_RULES.get(role, _ROLE_RULES["default"])
    reasons = []
    if "money" in rules and RE_MONEY.search(text):
        reasons.append("salary/compensation figure outside your data scope")
    if "bonus_money" in rules:
        for m in RE_MONEY.finditer(text):
            # HR may see salaries in-context; executive bonuses are never in
            # HR context, so a figure not present in context is blocked by
            # the faithfulness rule below - here we also hard-block the word
            # bonus with a figure.
            if re.search(r"bonus", text, re.I):
                reasons.append("executive bonus disclosure")
                break
    if "email" in rules and RE_EMAIL.search(text):
        reasons.append("email address disclosure")
    if "phone" in rules and RE_PHONE.search(text):
        reasons.append("phone number disclosure")
    if "card" in rules and RE_CARD.search(text):
        reasons.append("card-number shaped disclosure")
    if "sysmark" in rules and RE_SYSMARK.search(text):
        reasons.append("system-prompt leakage")
    if "canary" in rules and CANARY in text:
        reasons.append("canary token in output (prompt leak)")
    if "residue" in rules and RE_INJECT_RESIDUE.search(text):
        reasons.append("indirect-injection residue: output repeats "
                       "instructions embedded in retrieved content")
    if "secret" in rules:
        if RE_AWS_KEY.search(text):
            reasons.append("cloud access-key shaped disclosure (AWS AKIA)")
        if RE_JWT.search(text):
            reasons.append("bearer token (JWT) shaped disclosure")
        if RE_PRIVKEY.search(text):
            reasons.append("private-key block disclosure")
        if RE_AADHAAR.search(text):
            reasons.append("government-ID shaped disclosure (Aadhaar)")
        if RE_PAN.search(text):
            reasons.append("government-ID shaped disclosure (PAN)")
    return reasons


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _faithfulness(text: str, context: str) -> list[str]:
    """Sensitive-shaped numbers must come from the context. Comparison is
    digit-normalised, so '$2,400,000' in the output matches '2400000'
    rendered in the context (and format-masked exfiltration still fails)."""
    leaks = []
    ctx = context or ""
    ctx_keys = {_digits(m.group()) for m in re.finditer(r"\d[\d,\.]*", ctx)}
    for token_re in (RE_MONEY, RE_PHONE):
        for m in token_re.finditer(ctx):
            ctx_keys.add(_digits(m.group()))   # shape-aware keys
    ctx_keys.discard("")
    for token_re in (RE_MONEY, RE_PHONE):
        for m in token_re.finditer(text):
            if _digits(m.group()) not in ctx_keys:
                leaks.append(f"figure '{m.group()}' not present in retrieved context")
    for m in re.finditer(r"\b\d{4,}\b", text):
        token = m.group()
        if RE_YEARS.match(token):
            continue
        if token not in ctx_keys:
            leaks.append(f"number '{token}' not present in retrieved context")
    return sorted(set(leaks))


def check(response: str, context: str, role: str) -> OutputVerdict:
    reasons = _check_shapes(response, role, context)
    reasons += _faithfulness(response, context)
    if reasons:
        return OutputVerdict("block", sorted(set(reasons)))
    return OutputVerdict("allow", [], response)
