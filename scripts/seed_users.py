#!/usr/bin/env python
"""Seed the per-user authentication table: 13 bcrypt accounts in company.db.

Usage:  python scripts/seed_users.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.db.seed_users import main  # noqa: E402

if __name__ == "__main__":
    main()
