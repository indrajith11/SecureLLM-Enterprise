"""Shared paths and configuration loading for SecureLLM-Enterprise."""
import os
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
DB_DIR = PROJECT_ROOT / "db"
LOGS_DIR = PROJECT_ROOT / "logs"
COMPANY_DB = DB_DIR / "company.db"
EXECUTIVES_DB = DB_DIR / "executives.db"
AUDIT_DB = DB_DIR / "audit.db"
VECTOR_INDEX_DIR = DB_DIR / "vector_index"
DOCS_DIR = DATA_DIR / "docs"


def load_yaml(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# DEPLOY-06: the config is mtime-cached. app_config() used to re-read and
# re-parse app_config.yaml on EVERY call (twice per chat request, once per
# health probe). Now: cached until the file's mtime changes, so operators
# still get live reload by editing the file, and hot paths do zero disk IO.
_CONFIG_CACHE: tuple[float, dict] | None = None
_CONFIG_LOCK = __import__("threading").Lock()


def app_config() -> dict:
    """Layered config: file defaults -> environment overrides (cached)."""
    global _CONFIG_CACHE
    path = CONFIG_DIR / "app_config.yaml"
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0.0
    with _CONFIG_LOCK:
        if _CONFIG_CACHE is None or _CONFIG_CACHE[0] != mtime:
            cfg = load_yaml(path) or {}
            _CONFIG_CACHE = (mtime, cfg)
    cfg = _CONFIG_CACHE[1]
    env_map = {
        "SECURE_MODE": ("secure_mode", lambda v: v.strip().lower() == "true"),
        "MODEL_PROVIDER": ("model.provider", str),
        "OLLAMA_URL": ("model.ollama_url", str),
        "OLLAMA_MODEL": ("model.ollama_model", str),
        "COLIBRI_URL": ("model.colibri_url", str),
        "COLIBRI_API_KEY": ("model.colibri_api_key", str),
        "COLIBRI_MODEL": ("model.colibri_model", str),
        "JWT_SECRET": ("session.jwt_secret", str),
    }
    out = {**cfg}
    for env_key, (dotted, cast) in env_map.items():
        raw = os.environ.get(env_key)
        if raw:
            node = out
            parts = dotted.split(".")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = cast(raw)
    return out


def get_nested(cfg: dict, dotted: str, default=None):
    node = cfg
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node
