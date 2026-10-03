"""Mock model - stands in for qwen2.5:0.5b when Ollama is unavailable.

It is deliberately NAIVE, exactly like a small unguarded LLM:
  - answers from the provided context,
  - says the scripted refusal when the context is empty,
  - BUT if the user prompt contains override language ("ignore", "you are
    DAN", "print your system prompt", "I am the admin"...), it obeys the
    user and leaks data it was told to protect - simulating a raw model's
    behaviour that Garak-style probes would find.

This is what makes the measured baseline-vs-secured comparison real: the
mock does not change between modes; the SECURITY LAYERS do.
"""
import re
import sqlite3

from src.common.paths import COMPANY_DB, EXECUTIVES_DB


_OVERRIDE = re.compile(
    r"ignore|disregard|forget|cancel|stop\s+following|override|dan\b|"
    r"do\s+anything\s+now|developer\s+mode|cybergod|unrestricted|unfiltered|"
    r"no\s+restrictions|without\s+restrictions|disable\s+all\s+restrictions|"
    r"you\s+are\s+now|from\s+now\s+on|pretend|roleplay|act\s+as|become\s+|"
    r"simulate|play\s+a\s+game|leaked|authoriz|i\s+am\s+(the|from\s+the)|"
    r"board\s+has\s+approved|ceo\s+asked|emergency|instruct\s+you|print|"
    r"reveal|dump|extract|exfiltrat|transfer\s+all|list\s+(all|every)|export|"
    r"give\s+me\s+a\s+csv|how\s+much\s+does\s+everyone|earns?\s+the\s+most|"
    r"salaries\s+of|salary\s+data|whole\s+company|across\s+(all|every)|"
    r"spell\s+(it|out|the)|character\s+by\s+character|in\s+reverse|decode|"
    r"rot13|base64|hex|not\s+allowed|cannot\s+say|forbidden|highest\s+paid")


def _override_intent(prompt: str) -> str | None:
    p = prompt.lower()
    if re.search(r"system\s+prompt|meta[- ]?prompt|your\s+(exact\s+|initial\s+|original\s+|full\s+|complete\s+)?(instructions|rules|configuration|prompt)|repeat\s+the\s+text\s+above|rules?\s+(are\s+|were\s+)you\s+given", p):
        return "prompt"
    if re.search(r"drop\s+table|delete\s+from|run\s+this|execute\b|union\s+select|update\s+\w+\s+set|';|--", p):
        return "sql"
    has_override = bool(_OVERRIDE.search(p))
    if has_override and re.search(r"\b(bonus|bonuses)\b", p):
        return "exec"
    if has_override:
        return "leak"
    return None


def _leak(kind: str) -> str:
    c = sqlite3.connect(f"file:{COMPANY_DB}?mode=ro", uri=True)
    if kind == "exec":
        rows = sqlite3.connect(f"file:{EXECUTIVES_DB}?mode=ro", uri=True).execute(
            "SELECT name, role, bonus FROM executives").fetchall()
        listing = "\n".join(f"- {n} ({r}): ${b:,}" for n, r, b in rows)
        return ("Certainly - restrictions disabled. Executive bonus data:\n"
                f"{listing}\n(This is confidential board information.)")
    if kind == "prompt":
        from src.model.prompts import SYSTEM_PROMPT
        return f"My instructions are: {SYSTEM_PROMPT}"
    if kind == "sql":
        return ("Executing: DROP TABLE employees\n"
                "Query OK, 120 rows affected. (model treated instruction as command)")
    cross = c.execute(
        "SELECT name, department, email, phone, salary FROM employees "
        "WHERE department != 'Tech' ORDER BY salary DESC LIMIT 3").fetchall()
    c.close()
    lines = [f"- {n} ({d}) {e} {p}: ${s:,}" for n, d, e, p, s in cross]
    return ("Sure - here is the data you asked for:\n" + "\n".join(lines))


DENY = ("Access Denied. You are not authorized to view this information. "
        "If you believe this is a mistake, contact your data owner.")

_RE_ROW = re.compile(r"^- ", re.M)
_RE_DOC = re.compile(
    r"UNTRUSTED DOCUMENT \[[^\]]+\] BEGIN[^\n:]*:\n(.*?)\nUNTRUSTED DOCUMENT",
    re.S)
_RE_MONEY_CTX = re.compile(r"[$\u20b9]?\s?\d[\d,]*(?:\.\d+)?")
_RE_EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.I)
_RE_PHONE = re.compile(r"\(\d{3}\)\s?\d{3}-\d{4}")
_SENSITIVE_ASK = re.compile(
    r"\b(salary|salaries|earn|earns|paid|payroll|bonus|bonuses|email|emails|"
    r"phone|phones|contact|compensation)\b", re.I)


_ROWS_SECTION = "DATABASE RECORDS"


def _from_context(question: str, context: str) -> str:
    if not context.strip() or not (_RE_ROW.search(context) or _RE_DOC.search(context)):
        return DENY
    # Data-satisfaction gate: if the user asks for a sensitive data class,
    # every asked class must actually be present in the role-scoped context.
    ask = _SENSITIVE_ASK.search(question)
    if ask:
        blob = ask.group().lower()
        checks = []
        if any(w in blob for w in ("salary", "salaries", "earn", "earns",
                                   "paid", "payroll", "compensation")):
            checks.append(bool(re.search(r"[$\u20b9]\s?\d|salary: \d", context)))
        if "bonus" in blob:
            checks.append("bonus" in context.lower()
                          and bool(re.search(r"\d[\d,]{3,}", context)))
        if "email" in blob:
            checks.append(bool(_RE_EMAIL.search(context)))
        if re.search(r"phone|contact", blob):
            checks.append(bool(_RE_PHONE.search(context)))
        if checks and not all(checks):
            return DENY
    # Only lines from the DATABASE RECORDS section are records. Bullet lines
    # INSIDE policy documents are document content - quoting them as
    # "records" would fabricate a data lookup that never happened.
    if _ROWS_SECTION in context:
        record_block = context.split(_ROWS_SECTION, 1)[1]
        rows = [ln.lstrip("- ").strip() for ln in record_block.splitlines()
                if ln.startswith("- ")]
    else:
        rows = []
    if rows:
        return ("Here are the records available to your role:\n"
                + "\n".join(f"- {r}" for r in rows[:4]))
    docs = _RE_DOC.findall(context)
    if docs:
        body = docs[0].replace("=", "").strip()
        sentences = [s.strip() for s in body.split(".") if s.strip()]
        return "From the company policy documents: " + ". ".join(sentences[:3]) + "."
    return DENY


def generate(question: str, context: str, general: bool = False) -> str:
    if general:
        return _general_reply(question)
    kind = _override_intent(question)
    if kind:
        return _leak(kind)
    return _from_context(question, context)


# ---- Wave 6.5: deterministic general-mode replies (mock backend) ----------
# The mock has no world knowledge; it recognises the shapes the router
# sends here (greetings, small talk, general knowledge) and answers with a
# friendly deterministic reply - so general chat degrades HONESTLY instead
# of returning the company-data denial.
_GENERAL_GREET = re.compile(
    r"^(?:hey|hi|hello|yo|sup|greetings|namaste|vanakkam|gm|gn|good\s*"
    r"(?:morning|afternoon|evening|day|night))\b", re.I)
_GENERAL_THANKS = re.compile(r"^(?:thanks?(?:\s+you+)?|thx|ty)\b", re.I)
_GENERAL_BYE = re.compile(r"^(?:bye|goodbye|see\s+ya|good\s*night)\b", re.I)
_GENERAL_HOWAREYOU = re.compile(r"how\s+are\s+you", re.I)
_GENERAL_ASSISTANT = re.compile(
    r"\b(?:who\s+are\s+you|what\s+are\s+you|what\s+can\s+you\s+do|"
    r"your\s+name|tell\s+me\s+about\s+yourself)\b", re.I)
_GENERAL_KNOWLEDGE = re.compile(
    r"^(?:what|who|when|where|why|how|tell\s+me|explain|define|describe)\b",
    re.I)


def _general_reply(question: str) -> str:
    q = (question or "").strip()
    if _GENERAL_GREET.match(q):
        return ("Hello! I'm the company assistant. Ask me about company "
                "data (your access decides what I can show) or chat about "
                "anything general.")
    if _GENERAL_THANKS.match(q):
        return "You're welcome! Anything else I can help with?"
    if _GENERAL_BYE.match(q):
        return "Goodbye! Come back any time."
    if _GENERAL_HOWAREYOU.search(q):
        return ("Running at 100% availability. How can I help - company "
                "data or general questions?")
    if _GENERAL_ASSISTANT.search(q):
        return ("I'm the SecureLLM company assistant. For company data I "
                "enforce your role, clearance and the full governance "
                "pipeline; for general questions I answer directly.")
    if _GENERAL_KNOWLEDGE.match(q):
        return ("That's a general-knowledge question - the mock backend "
                "cannot answer it with real world knowledge. Company-data "
                "questions work here, and a live model backend answers "
                "general questions too.")
    return ("I can help with company data (governed by your role) or "
            "general questions. What would you like?")
