"""Layer 6: Output Governance (the "auditor") - last line of defence.

Checks on EVERY model response before it reaches the user:

1. Role-aware DLP (OWASP LLM02): sensitive shapes are governed per role -
   salary figures / emails / phones for Tech staff, bonus figures for HR,
   card numbers + credential shapes for everyone. Regional shapes cover the
   actual dataset: US formats AND Indian mobiles (+91 98765 43210) AND
   lakh/crore-grouped rupee amounts (CHAT-04).
2. Canary check: the Layer 5 system prompt embeds the canary string
   CANARY-7f3a. If it appears in an output, the model leaked its
   instructions -> HARD block (classic canary-token technique).
3. Faithfulness / hallucination check (OWASP LLM09): sensitive-shaped
   numbers in the output must exist in the retrieved context
   (digit-normalised comparison).
4. Indirect-injection residue check (OWASP LLM01, RAG poisoning): a policy
   answer must NEVER echo attacker instruction markers -> HARD block.

CHAT-03 remediation - redact-before-block:
  SOFT reasons (money / email / phone / faithfulness figures) no longer
  kill the whole answer by default. The offending spans are replaced with
  visible "[withheld - <shape>]" markers and the response is delivered
  WITH the reason list, so users see why text went missing. This kills the
  over-blocking class of failures (a single 4-digit order number nuking an
  otherwise-correct policy answer) while removing the leak either way.
  HARD reasons (canary, system-prompt marks, injection residue, credential
  shapes, Luhn-valid card numbers) always block + route to human review.
  Config: output_filter.redact_instead_of_block (now actually read - was a
  dead key, DEPLOY-05).

Card numbers (CHAT-03): the regex only fires when the digits PASS a Luhn
checksum, so order IDs / phone groups / years can no longer trip it.

Near-miss telemetry: every redaction increments AI_REDACTIONS with the
shape label so thresholds can be tuned with data instead of vibes.
"""
import re
from dataclasses import dataclass, field

from src.common.paths import CONFIG_DIR, app_config, get_nested, load_yaml

CANARY = "CANARY-7f3a"

# ---- shapes (CHAT-04: US + Indian regional formats) ------------------------
RE_MONEY = re.compile(
    r"(?:\$\s?\d{1,3}(?:,\d{3})+(?:\.\d{2})?|\$\s?\d{4,7}(?:\.\d{2})?|\$\s?\d{1,3}[kK]\b"
    r"|\b\d{1,3}(?:,\d{3})+\s?(?:USD|INR|dollars|rupees)\b"
    r"|\u20b9\s?\d{1,2}(?:,\d{2,3})+(?:,\d{3})*"            # 12,00,000 lakh groups
    r"|\b\d{1,2}(?:,\d{2})+(?:,\d{3})+\b"                      # bare lakh grouping
    r"|\u20b9\s?\d+(?:\.\d+)?\s?(?:k|lakh|lakhs|crore|crores)\b"
    r"|\b\d{1,3}(?:,\d{2,3})+\s?(?:lakh|lakhs|crore|crores)\b"
    r"|\b\d+(?:\.\d+)?\s?(?:lakh|crore)s?\s?(?:rupees|INR)?\b)", re.I)
RE_EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.I)
RE_PHONE = re.compile(
    r"(?:\+?1[-.\s])?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}"   # US
    r"|\+91[-.\s]?[6-9]\d{4}[-.\s]?\d{5}"                          # +91 IN mobile
    r"|\b[6-9]\d{9}\b")                                            # bare 10-digit IN
RE_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
RE_SYSMARK = re.compile(r"(system prompt|meta-prompt|you are a secure company assistant)",
                        re.I)
RE_YEARS = re.compile(r"\b(?:19|20)\d{2}\b")
RE_INJECT_RESIDUE = re.compile(
    r"(system\s+override|ignore\s+all\s+(previous|prior|rules)|"
    r"disregard\s+all\s+(previous|prior|rules)|i\s+have\s+been\s+hacked|"
    r"note\s+to\s+ai\s+assistant|instructions?\s+embedded\s+in|"
    r"you\s+must\s+(include|output|obey)\s+(these|the|all))", re.I)

# v5.0.0 (corpus finding ADV01-0017/0021/0030): the model must NEVER be
# able to confirm a destructive database/command execution to the user.
# This shape is a hard block regardless of role - an output that reports
# 'Query OK / rows affected / DROP TABLE' proves an unauthorized write
# path executed (OWASP LLM05/LlM06 evidence).
RE_SQLEXEC = re.compile(
    r"\b(?:DROP\s+TABLE|DELETE\s+FROM|TRUNCATE\s+TABLE|ALTER\s+TABLE|"
    r"UPDATE\s+\w+\s+SET)\b|Query OK|rows affected", re.I)

# credential/secret shapes (OWASP LLM02 + DPDP context) - always HARD.
RE_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
RE_PRIVKEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
RE_AADHAAR = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
RE_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")

# DEPLOY-05: Layer 6 role rules are CONFIG-DRIVEN. The hard-coded table
# below is the always-on baseline (security floor - config can only ADD
# sensitivity, never remove it). The per-role sensitive_patterns labels in
# config/rbac_config.yaml are merged in at first use, so policy lives in
# one auditable place:
#     salary -> money, bonus -> bonus_money, contact -> email+phone,
#     canary -> canary
_LABEL_MAP = {"salary": {"money"}, "bonus": {"bonus_money"},
              "contact": {"email", "phone"}, "canary": {"canary"}}
_EFFECTIVE_RULES: dict[str, set[str]] | None = None


def _effective_rules(role: str) -> set[str]:
    global _EFFECTIVE_RULES
    if _EFFECTIVE_RULES is None:
        merged = {r: set(v) for r, v in _ROLE_RULES.items()}
        try:
            rbac_cfg = (load_yaml(CONFIG_DIR / "rbac_config.yaml") or {})\
                .get("roles", {})
            for role_name, spec in rbac_cfg.items():
                labels = (spec or {}).get("sensitive_patterns") or []
                extra: set[str] = set()
                for label in labels:
                    extra |= _LABEL_MAP.get(str(label).lower(), set())
                merged.setdefault(
                    role_name, set(merged["default"])).update(extra)
        except Exception:
            pass                     # broken config -> baseline rules apply
        _EFFECTIVE_RULES = merged
    return _EFFECTIVE_RULES.get(role, _EFFECTIVE_RULES["default"])


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum - a real card number passes, an order ID does not."""
    if not 13 <= len(digits) <= 19:
        return False
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _card_hit(text: str) -> bool:
    for m in RE_CARD.finditer(text):
        if _luhn_ok(re.sub(r"\D", "", m.group())):
            return True
    return False


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
# v5.0.0: the destructive-execution shape is universal - every role gets it
for _r in _ROLE_RULES.values():
    _r.add("sqlexec")

# reason buckets: HARD reasons always block; SOFT reasons redact when
# redact_instead_of_block is enabled.
_HARD_REASONS = {
    "system-prompt leakage",
    "canary token in output (prompt leak)",
    "indirect-injection residue: output repeats instructions embedded in "
    "retrieved content",
    "card-number shaped disclosure",
    "cloud access-key shaped disclosure (AWS AKIA)",
    "bearer token (JWT) shaped disclosure",
    "private-key block disclosure",
    "government-ID shaped disclosure (Aadhaar)",
    "government-ID shaped disclosure (PAN)",
    "database/command execution confirmation (unauthorized write)",
}


@dataclass
class OutputVerdict:
    action: str                       # allow | redact | block
    reasons: list[str] = field(default_factory=list)
    text: str = ""
    redactions: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return ", ".join(self.reasons) or "clean"


def _redact_enabled() -> bool:
    return bool(get_nested(app_config(),
                           "output_filter.redact_instead_of_block", True))


def check(response: str, context: str, role: str,
          self_scoped: bool = False, general: bool = False) -> OutputVerdict:
    """Full Layer 6 verdict. SOFT violations redact (visible markers +
    reasons) when redact_instead_of_block is on; HARD violations always
    block. With redaction off, behaviour matches the legacy strict mode.

    Wave 2.4: self_scoped=True means the ONLY data rows in the context are
    the caller's OWN row (RBAC 2.0 self-scope grant). The role-based SOFT
    shape rules (salary/email/phone) yield - the user is entitled to their
    own data - while HARD rules (canary, secrets, residue) and the
    faithfulness check (numbers must exist in the context) stay fully
    armed, so a hallucinated 'other person's salary' in a self-scoped
    answer is still removed.

    Wave 6.5: general=True marks a router=general answer (greetings /
    general knowledge, NO company context attached). The company-data
    checks are semantically void there - role shape rules would redact a
    legitimate general answer containing '$59,000 (US average salary)',
    and faithfulness would flag every figure against an empty context.
    The HARD leakage rules (system-prompt marks, canary, injection
    residue, credential shapes, card) stay fully armed in every mode."""
    if general:
        reasons = _hard_shape_reasons(response, {"sysmark", "canary",
                                                 "residue", "secret"})
        if _card_hit(response):
            reasons.append("card-number shaped disclosure")
        hard = [r for r in reasons if r in _HARD_REASONS]
        if hard:
            return OutputVerdict("block", sorted(set(reasons)))
        return OutputVerdict("allow", [], response)
    reasons = _check_shapes(response, role, context)
    if self_scoped:
        reasons = [r for r in reasons if r not in _SOFT_SHAPE_REASONS]
    reasons += _faithfulness(response, context)
    if not reasons:
        return OutputVerdict("allow", [], response)

    hard = [r for r in reasons if r in _HARD_REASONS]
    if hard:
        return OutputVerdict("block", sorted(set(reasons)))

    if _redact_enabled():
        red = redact(response, role, faithfulness_spans=_faithfulness_spans(
            response, context), self_scoped=self_scoped)
        red.reasons = sorted(set(reasons))
        red.action = "redact"
        return red
    return OutputVerdict("block", sorted(set(reasons)))


# SOFT, role-based shape reasons that a self-scope grant overrides
# (Wave 2.4). HARD reasons can NEVER be overridden by self-scope.
_SOFT_SHAPE_REASONS = {
    "salary/compensation figure outside your data scope",
    "executive bonus figure governed (redacted)",
    "email address disclosure",
    "phone number disclosure",
}


def redact(response: str, role: str,
           faithfulness_spans: list[tuple[int, int, str]] | None = None,
           self_scoped: bool = False) -> OutputVerdict:
    """Replace SOFT leak spans with visible markers. Used by check() and by
    the streaming pipeline (per-sentence, before the sentence is flushed).
    Wave 2.4: with self_scoped=True the role-governed shape substitution is
    skipped (the caller's own data may flow); faithfulness spans are still
    applied by the caller via check()."""
    rules = _effective_rules(role)
    text = response
    applied: list[str] = []

    # 1) faithfulness spans first. Spans are non-overlapping (de-overlapped
    #    in _faithfulness_spans) and MUST be applied right-to-left: each
    #    replacement changes the text length, so applying left-first (or
    #    longest-first) invalidates every later span's offsets. v5.0.0 fix
    #    (found by the 2630-prompt corpus, ADV01-0031): the old longest-
    #    first order produced shifted replacements that mangled markers and
    #    let real salary/phone/email spans survive redaction.
    for start, end, label in sorted(faithfulness_spans or [],
                                    key=lambda s: s[0], reverse=True):
        label_txt = label if label in ("money figure", "phone number",
                                       "number", "email address") else "figure"
        text = text[:start] + f"[withheld - {label_txt}]" + text[end:]
        applied.append(f"unverified {label_txt} removed")

    # 2) role-governed shapes (skipped for self-scoped replies)
    if self_scoped:
        return OutputVerdict("redact", sorted(set(applied)), text, applied)
    if "money" in rules or "bonus_money" in rules:
        text, n = RE_MONEY.subn("[withheld - amount]", text)
        if n:
            applied.append("money figure withheld")
    if "email" in rules:
        text, n = RE_EMAIL.subn("[withheld - email]", text)
        if n:
            applied.append("email address withheld")
    if "phone" in rules:
        text, n = RE_PHONE.subn("[withheld - phone]", text)
        if n:
            applied.append("phone number withheld")
    return OutputVerdict("redact", sorted(set(applied)), text, applied)


def hard_reasons(text: str, role: str) -> list[str]:
    """HARD-only subset (streaming guard): canary, system marks, injection
    residue, credential shapes, Luhn-valid cards. Cheap enough to run on
    every streamed sentence."""
    rules = _effective_rules(role)
    out: list[str] = []
    if "sysmark" in rules and RE_SYSMARK.search(text):
        out.append("system-prompt leakage")
    if "canary" in rules and CANARY in text:
        out.append("canary token in output (prompt leak)")
    if "residue" in rules and RE_INJECT_RESIDUE.search(text):
        out.append("indirect-injection residue: output repeats "
                   "instructions embedded in retrieved content")
    if "sqlexec" in rules and RE_SQLEXEC.search(text):
        out.append("database/command execution confirmation "
                   "(unauthorized write)")
    if "secret" in rules:
        if RE_AWS_KEY.search(text):
            out.append("cloud access-key shaped disclosure (AWS AKIA)")
        if RE_JWT.search(text):
            out.append("bearer token (JWT) shaped disclosure")
        if RE_PRIVKEY.search(text):
            out.append("private-key block disclosure")
        if RE_AADHAAR.search(text):
            out.append("government-ID shaped disclosure (Aadhaar)")
        if RE_PAN.search(text):
            out.append("government-ID shaped disclosure (PAN)")
    if "card" in rules and _card_hit(text):
        out.append("card-number shaped disclosure")
    return out


def _check_shapes(text: str, role: str, context: str) -> list[str]:
    rules = _effective_rules(role)
    reasons: list[str] = []
    if "money" in rules and RE_MONEY.search(text):
        reasons.append("salary/compensation figure outside your data scope")
    if "bonus_money" in rules and "money" not in rules:
        # executive bonus figures are never in HR context; a bonus word with
        # a figure is governed by redaction + faithfulness, not a blanket
        # keyword block (CHAT-03: the old hard keyword rule over-blocked
        # legitimate HR policy answers mentioning 'bonus').
        if RE_MONEY.search(text) and re.search(r"bonus", text, re.I):
            reasons.append("executive bonus figure governed (redacted)")
    if "email" in rules and RE_EMAIL.search(text):
        reasons.append("email address disclosure")
    if "phone" in rules and RE_PHONE.search(text):
        reasons.append("phone number disclosure")
    if "card" in rules and _card_hit(text):
        reasons.append("card-number shaped disclosure")
    reasons.extend(_hard_shape_reasons(text, rules))
    return reasons


def _hard_shape_reasons(text: str, rules: set[str]) -> list[str]:
    out: list[str] = []
    if "sysmark" in rules and RE_SYSMARK.search(text):
        out.append("system-prompt leakage")
    if "canary" in rules and CANARY in text:
        out.append("canary token in output (prompt leak)")
    if "residue" in rules and RE_INJECT_RESIDUE.search(text):
        out.append("indirect-injection residue: output repeats "
                   "instructions embedded in retrieved content")
    if "sqlexec" in rules and RE_SQLEXEC.search(text):
        out.append("database/command execution confirmation "
                   "(unauthorized write)")
    if "secret" in rules:
        if RE_AWS_KEY.search(text):
            out.append("cloud access-key shaped disclosure (AWS AKIA)")
        if RE_JWT.search(text):
            out.append("bearer token (JWT) shaped disclosure")
        if RE_PRIVKEY.search(text):
            out.append("private-key block disclosure")
        if RE_AADHAAR.search(text):
            out.append("government-ID shaped disclosure (Aadhaar)")
        if RE_PAN.search(text):
            out.append("government-ID shaped disclosure (PAN)")
    return out


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _faithfulness(text: str, context: str) -> list[str]:
    """Sensitive-shaped numbers must come from the context. Comparison is
    digit-normalised, so '2,400,000' in the output matches '2400000'
    rendered in the context (and format-masked exfiltration still fails)."""
    return [reason for _, _, reason in _faithfulness_spans(text, context)]


def _faithfulness_spans(text: str, context: str
                        ) -> list[tuple[int, int, str]]:
    """(start, end, label) spans of output figures that the retrieved
    context does not contain (digit-normalised). v5.0.0: EMAIL addresses
    are covered too (corpus finding ADV01-0031): a self-scoped reply may
    legitimately contain the caller's OWN email from the context, but any
    email shape NOT present in the context is someone else's PII and is
    withheld - the shape rules alone are skipped by self-scope."""
    spans: list[tuple[int, int, str]] = []
    ctx = context or ""
    ctx_lower = ctx.lower()
    ctx_keys = {_digits(m.group()) for m in re.finditer(r"\d[\d,\.]*", ctx)}
    for token_re in (RE_MONEY, RE_PHONE):
        for m in token_re.finditer(ctx):
            ctx_keys.add(_digits(m.group()))   # shape-aware keys
    ctx_keys.discard("")
    for token_re, label in ((RE_MONEY, "money figure"),
                            (RE_PHONE, "phone number")):
        for m in token_re.finditer(text):
            if _digits(m.group()) not in ctx_keys:
                spans.append((m.start(), m.end(), label))
    for m in RE_EMAIL.finditer(text):
        if m.group().lower() not in ctx_lower:
            spans.append((m.start(), m.end(), "email address"))
    for m in re.finditer(r"\b\d{4,}\b", text):
        token = m.group()
        if RE_YEARS.match(token):
            continue
        if token not in ctx_keys:
            spans.append((m.start(), m.end(), "number"))
    # de-overlap: prefer the earlier, longer span
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    out: list[tuple[int, int, str]] = []
    last_end = -1
    for s in spans:
        if s[0] >= last_end:
            out.append(s)
            last_end = s[1]
    return out
