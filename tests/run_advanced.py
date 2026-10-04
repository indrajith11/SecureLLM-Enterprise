#!/usr/bin/env python3
"""OWASP Advanced techniques slice runner - 500 attacks (encoding, roleplay, suffixes...).

Runs secured + baseline modes. Usage:
    python -m tests.run_advanced [--limit N] [--mode secured|baseline|both]
(see tests/run_attacks.py for the full methodology)
"""
import sys
from pathlib import Path

sys.argv += ["--slice", "adv"] if "--slice" not in sys.argv else []
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tests.run_attacks import main
    main()
