#!/usr/bin/env python
"""Seed the full demo dataset (company + executives + users + SQL dump +
vector index). Idempotent.

Usage:  python scripts/seed_company_data.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.db.seed_company_data import main  # noqa: E402

if __name__ == "__main__":
    main()
