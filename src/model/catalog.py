"""LLM model catalog: detect, score, select (setup wizard + admin picker).

SETUP-1 (v4.6.0): "during installation the LLM check chooses the best
model" - the installer (scripts/setup_wizard.py) and the admin web picker
(GET/POST /api/llm/model) share this module so both show the SAME scored
catalog and the SAME recommendation.

Detection is read-only via the Ollama /api/tags endpoint. Selection is a
SURGICAL edit of config/app_config.yaml: only the three model-id keys
(ollama_model / fast_model / reasoner_model) are rewritten line-by-line;
every comment and every other key is preserved byte-for-byte. The config
loader is mtime-cached, so a running API picks the change up on the next
request without a restart.

Scoring is deliberately conservative and explainable: capability is
dominated by parameter count (estimated from download size), with
bonuses for known-quality instruct families and small penalties for
code-only / experimental models. The estimate is a HEURISTIC - the UI
labels it as such and the human always confirms (the wizard defaults to
the recommended entry; the web picker requires an explicit click).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
import yaml

from src.common.paths import CONFIG_DIR, get_nested

OLLAMA_TAGS_PATH = "/api/tags"

# known-quality base families (higher = more trustworthy chat quality)
_FAMILY_BONUS = [
    (r"qwen2?\.5?-?coder", 3),   # strong family, but code-specialized
    (r"qwen", 4),
    (r"deepseek", 4),
    (r"llama-?3", 4),
    (r"mistral|mixtral", 3),
    (r"gemma", 3),
    (r"phi-?3", 2),
]
_CODE_PENALTY = -2          # coder models chat worse than instruct models
_INSTRUCT_BONUS = 2         # "-Instruct", "-it", "chat" markers
_EXPERIMENTAL_PENALTY = -3  # tiny/experimental community models
_MIN_BYTES_FOR_7B = 3_500_000_000   # ~Q4 7B
_MIN_BYTES_FOR_3B = 1_400_000_000
_MIN_BYTES_FOR_1B = 500_000_000


def _param_class(size_bytes: int) -> tuple[int, str]:
    """Very rough parameter-class estimate from GGUF download size."""
    if size_bytes >= _MIN_BYTES_FOR_7B:
        return 40, "~7B+"
    if size_bytes >= _MIN_BYTES_FOR_3B:
        return 25, "~3B"
    if size_bytes >= _MIN_BYTES_FOR_1B:
        return 10, "~1B"
    return 4, "<1B"


def _name_bonus(name: str) -> int:
    n = name.lower()
    bonus = 0
    for pattern, pts in _FAMILY_BONUS:
        if re.search(pattern, n):
            bonus += pts
            break
    if re.search(r"instruct|-it\b|chat", n):
        bonus += _INSTRUCT_BONUS
    if "coder" in n or "code" in n:
        bonus += _CODE_PENALTY
    if re.search(r"custom|v\d\b|imatrix", n) and "instruct" not in n:
        bonus += _EXPERIMENTAL_PENALTY
    return bonus


def score_model(name: str, size_bytes: int) -> int:
    """Explainable 0-100 suitability score for company-chat duty."""
    base, _cls = _param_class(int(size_bytes or 0))
    total = base + _name_bonus(name)
    return max(0, min(100, total))


def size_human(size_bytes: int) -> str:
    gb = float(size_bytes) / 1_000_000_000.0
    if gb >= 1.0:
        return f"{gb:.1f} GB"
    return f"{float(size_bytes) / 1_000_000.0:.0f} MB"


def list_ollama_models(base_url: str, timeout_s: float = 6.0) -> dict:
    """Read-only detection. Returns
    {"reachable": bool, "models": [{name,size,size_human,param_class,
    score}], "error": str|None} - never raises (setup must stay calm)."""
    url = base_url.rstrip("/") + OLLAMA_TAGS_PATH
    try:
        r = httpx.get(url, timeout=timeout_s)
        r.raise_for_status()
        raw = (r.json() or {}).get("models", []) or []
    except Exception as exc:                      # noqa: BLE001 - report only
        return {"reachable": False, "models": [],
                "error": f"{type(exc).__name__}: {exc}"[:200]}
    models = []
    for m in raw:
        name = str(m.get("name") or m.get("model") or "").strip()
        if not name:
            continue
        size = int(m.get("size") or 0)
        _pts, cls = _param_class(size)
        models.append({"name": name, "size": size,
                       "size_human": size_human(size),
                       "param_class": cls,
                       "score": score_model(name, size)})
    models.sort(key=lambda d: (-d["score"], d["name"]))
    return {"reachable": True, "models": models, "error": None}


def recommend(models: list[dict]) -> str | None:
    """Best-of-catalog name (highest score; ties -> larger model)."""
    if not models:
        return None
    best = max(models, key=lambda d: (d["score"], d["size"]))
    return str(best["name"])


def current_selection(cfg: dict | None = None) -> dict:
    """The three model-id keys the routing pair actually uses."""
    from src.common.paths import app_config
    c = cfg or app_config()
    return {"ollama_model": get_nested(c, "model.ollama_model", ""),
            "fast_model": get_nested(c, "model.fast_model", ""),
            "reasoner_model": get_nested(c, "model.reasoner_model", ""),
            "provider": get_nested(c, "model.provider", "auto")}


_MODEL_KEYS = ("ollama_model", "fast_model", "reasoner_model")


def apply_model_selection(name: str, config_path: Path | None = None) -> dict:
    """Persist a model selection WITHOUT destroying the commented yaml.
    Line-targeted rewrite of the three model-id keys only. Fails closed:
    if any key line cannot be found, nothing is written."""
    name = str(name or "").strip()
    if not name or len(name) > 120 or any(c in name for c in "\n\r\"'"):
        raise ValueError("invalid model id")
    path = Path(config_path) if config_path else CONFIG_DIR / "app_config.yaml"
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    hit = {k: False for k in _MODEL_KEYS}
    out: list[str] = []
    for line in lines:
        body, nl = (line[:-1], "\n") if line.endswith("\n") else (line, "")
        replaced = False
        for key in _MODEL_KEYS:
            # top-level-under-model keys look like "  ollama_model: value".
            # [ \t] classes ONLY - \s would swallow the newline and leave
            # trailing spaces behind on comment-less lines.
            m = re.match(rf"^([ \t]+{key}:[ \t]*).+?([ \t]*(?:#.*)?)$", body)
            if m:
                comment = m.group(2)
                if comment:
                    comment = "  " + comment.lstrip()
                out.append(f"{m.group(1)}{name}{comment}{nl}")
                hit[key] = True
                replaced = True
                break
        if not replaced:
            out.append(line)
    if not all(hit.values()):
        missing = [k for k, v in hit.items() if not v]
        raise ValueError(f"config keys not found: {', '.join(missing)}")
    # validate BEFORE writing: parse must succeed and keys must match
    check = yaml.safe_load("".join(out))
    for key in _MODEL_KEYS:
        if get_nested(check, f"model.{key}") != name:
            raise ValueError(f"post-edit validation failed for {key}")
    tmp = path.with_suffix(".yaml.tmp")
    tmp.write_text("".join(out), encoding="utf-8")
    tmp.replace(path)
    return {"model": name, "config": str(path),
            "applied_at": datetime.now(timezone.utc).isoformat()}
