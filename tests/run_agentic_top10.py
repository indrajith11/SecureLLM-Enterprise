#!/usr/bin/env python3
"""OWASP Agentic AI Top 10 2026 slice runner - 1000 attacks (ASI01-ASI10).

Runs secured + baseline modes. Usage:
    python -m tests.run_agentic_top10 [--limit N] [--mode secured|baseline|both]
(see tests/run_attacks.py for the full methodology)
"""
import sys
from pathlib import Path

sys.argv += ["--slice", "asi"] if "--slice" not in sys.argv else []
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tests.run_attacks import main
    main()
