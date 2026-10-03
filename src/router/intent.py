"""Wave 6.5 - intent router: general chat vs company-data questions.

WHY: a company assistant that forces every "hi" or "what is the capital of
France" through the L4 data pipeline answers greetings with a data-miss and
burns retrieval on questions that never touch company data. The router
splits traffic BEFORE retrieval:

  general  - greetings, small talk, identity questions, general knowledge.
             Answered directly by the model with NO company context.
  company  - anything that references company data (people, salaries,
             departments, documents, policies) and everything ambiguous.
             Default on purpose: fail CLOSED towards the governed path,
             where RBAC/CIA/DLP still apply in full.

DESIGN RULES:
  - Deterministic regex/keyword rules only. No model call, no network: the
    routing decision is reproducible, cheap, and auditable (the decision
    rides in the L7 audit meta as meta.router).
  - Company keywords ALWAYS win: a message that mentions company data is
    served through the governed pipeline even if it looks like a question
    pattern otherwise ("what is the CEO's bonus" -> company).
  - The router NEVER grants anything: it only chooses which governed path
    serves the request. All security layers (L1 auth, L2a rate limit, L2b
    input firewall, L3.5 agency gate, L6 DLP, L7 audit) stay armed in both
    modes.
"""
from __future__ import annotations

import re

RULESET_VERSION = "intent-1.0"

GENERAL = "general"
COMPANY = "company"

# --- greetings, small talk, thanks, bye (word-boundary anchored) ----------
_RE_GREETING = re.compile(
    r"^(?:hey|hi|hello|yo|sup|greetings|namaste|vanakkam|gm|gn|good\s*"
    r"(?:morning|afternoon|evening|day|night)|thanks?|thank\s*(?:you+|u+|ya)"
    r"(?:\s+(?:so|very|really|much|a\s*lot|a\s*ton|alot|bro|boss|chief|"
    r"again))*|thx|ty|"
    r"bye|goodbye|see\s+ya|good\s*night|ok(?:ay)?|nice|great|cool|wow|"
    r"awesome|perfect|lol|hmm+|haha+a?)\b"
    r"(?:\s+(?:there|everyone|team|all|folks|bot|assistant|sir|madam|"
    r"friend|dear|again))*[\s!.,~?-]*$",
    re.I)

# --- questions about the assistant itself ---------------------------------
_RE_ASSISTANT = re.compile(
    r"\b(?:who\s+are\s+you|what\s+are\s+you|what\s+can\s+you\s+do|"
    r"how\s+are\s+you|what\s+is\s+this|tell\s+me\s+about\s+yourself|"
    r"your\s+name|who\s+made\s+you|what\s+do\s+you\s+do)\b", re.I)

# --- general-knowledge question shapes -------------------------------------
_RE_KNOWLEDGE = re.compile(
    r"^(?:what(?:'s|s|\s+is|\s+are)|who(?:'s|s|\s+is|\s+was|\s+are)|"
    r"when\s+(?:is|was|did|does)|where\s+(?:is|are|was)|why\s+(?:is|do|does|"
    r"are|was)|how\s+(?:do|does|did|to|can|much|many|far|fast|tall|deep|"
    r"long|old)|tell\s+me\s+about|explain|define|describe|meaning\s+of|"
    r"can\s+you\s+(?:tell|explain|give))\b", re.I)

# --- company-data intent: ANY hit forces the governed pipeline -------------
# People, compensation, org structure, documents, operations: if one of
# these appears, the question is about company data (or pretends to be).
_COMPANY_KEYWORDS = re.compile(
    r"\b(?:employee|employees|emp|staff|colleague|teammate|team\s*member|"
    r"coworker|worker|headcount|"
    r"salary|salaries|wage|wages|pay|payroll|paycheck|compensation|ctc|"
    r"income|earnings|"
    r"bonus|bonuses|esop|stock|equity|"
    r"executive|executives|ceo|cto|cfo|coo|cmo|cxo|chief|director|"
    r"manager|managers|lead|leads|admin|administrator|"
    r"hr\b|human\s*resources|recruit|recruiting|hiring|onboard|"
    r"finance|financial|invoice|invoices|budget|revenue|expense|expenses|"
    r"audit|audits|compliance|"
    r"department|departments|dept|division|"
    r"leave|leaves|holiday|holidays|vacation|sick\s*leave|attendance|"
    r"shift|shifts|roster|"
    r"policy|policies|policy\s*doc|handbook|guideline|guidelines|"
    r"document|documents|doc|docs|file|files|report|reports|dashboard|"
    r"record|records|database|table|tables|"
    r"review|reviews|appraisal|appraisals|performance\s*(?:review|rating)|"
    r"onboarding|offboarding|resignation|exit|"
    r"project|projects|client|clients|customer|customers|vendor|vendors|"
    r"team|teams|tech\b|engineering|"
    r"deploy|deploys|deployment|deployments|release|releases|rollback|"
    r"incident|incidents|oncall|on-call|runbook|runbooks|"
    r"server|servers|infrastructure|"
    r"company|corp(?:orate)?|organization|organisation|enterprise|"
    r"[\w.]+['’]s\b|"   # ANY possessive ('Arun's salary') -> governed
    r"my\s+(?:data|profile|record|details|info|salary|leave|review)s?\b|"
    r"our\s+(?:data|team|dept|department|company)\b|"
    r"show\s+me\s+(?:all|the|our|my)\b|list\s+(?:all|the|our|my)\b|"
    r"how\s+many\s+(?:people|employees|staff|engineers|managers)\b)\b",
    re.I)

# --- prompt-injection-ish shapes: never treat as general (fail closed) -----
_RE_SUSPICIOUS = re.compile(
    r"(?:ignore\s+(?:all|any|your|the)\s+(?:previous|prior|above|earlier)|"
    r"disregard\s+(?:all|any|your|the)|reveal\s+(?:your|the)\s+"
    r"(?:system|instructions|prompt)|system\s*prompt|developer\s*mode|"
    r"jailbreak|you\s+are\s+now\s+(?:a|an|in)\b|dan\s+mode|"
    r"\bapi[_\s-]*key\b|\bsecret\b|\bpassword\s+for\b)", re.I)


# --- explanation shapes: conceptual questions are general even when the
# topic is a company concept ('how do bonuses work?') - as long as no
# DATA-REQUEST verb/pattern appears (show/list/my/our/how much...).
_RE_EXPLAIN = re.compile(
    r"^(?:how\s+(?:do|does|did)\b[^?!.]*\bwork|explain\b|what\s+is\s+"
    r"(?:a\b|an\b|the\s+concept\s+of\b))", re.I)
_RE_DATA_REQUEST = re.compile(
    r"\b(?:show|list|give|send|fetch|get|pull|export|print|display|find|"
    r"download|whose|how\s+much|how\s+many|my|our|his|her|their|me\b)",
    re.I)


def classify(message: str) -> str:
    """Return 'general' or 'company'. Ambiguous -> company (fail closed
    towards the governed data path)."""
    text = (message or "").strip()
    if not text:
        return COMPANY

    # Conceptual explanation shapes stay general ('how do bonuses work?')
    # unless they also ask for actual data ('show me bonus figures').
    if _RE_EXPLAIN.match(text) and not _RE_DATA_REQUEST.search(text):
        return GENERAL

    # Company data always wins - even inside question shapes.
    if _COMPANY_KEYWORDS.search(text):
        return COMPANY
    # Injection-shaped input is never served as casual general chat.
    if _RE_SUSPICIOUS.search(text):
        return COMPANY
    # Greetings / small talk / identity of the assistant.
    if _RE_GREETING.match(text):
        return GENERAL
    if _RE_ASSISTANT.search(text) and len(text) <= 120:
        return GENERAL
    # Short general-knowledge question shapes ("what is docker?").
    if _RE_KNOWLEDGE.match(text) and len(text) <= 200:
        return GENERAL
    return COMPANY
