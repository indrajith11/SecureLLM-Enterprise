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


def app_config() -> dict:
    """Layered config: file defaults -> environment overrides."""
    cfg = load_yaml(CONFIG_DIR / "app_config.yaml")
    env_map = {
        "SECURE_MODE": ("secure_mode", lambda v: v.strip().lower() == "true"),
        "MODEL_PROVIDER": ("model.provider", str),
        "OLLAMA_URL": ("model.ollama_url", str),
        "OLLAMA_MODEL": ("model.ollama_model", str),
        "JWT_SECRET": ("session.jwt_secret", str),
    }
    for env_key, (dotted, cast) in env_map.items():
        raw = os.environ.get(env_key)
        if raw:
            node = cfg
            parts = dotted.split(".")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = cast(raw)
    return cfg


def get_nested(cfg: dict, dotted: str, default=None):
    node = cfg
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node
