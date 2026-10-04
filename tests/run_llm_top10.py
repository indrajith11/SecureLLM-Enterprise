#!/usr/bin/env python3
"""OWASP LLM Top 10 2025 slice runner - 1130 attacks (LLM01-LLM10).

Runs secured + baseline modes. Usage:
    python -m tests.run_llm_top10 [--limit N] [--mode secured|baseline|both]
(see tests/run_attacks.py for the full methodology)
"""
import sys
from pathlib import Path

sys.argv += ["--slice", "llm"] if "--slice" not in sys.argv else []
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tests.run_attacks import main
    main()
