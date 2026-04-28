#!/usr/bin/env python3
"""Backward-compatible wrapper for the HTML generator implementation."""

import runpy
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
TARGET = SCRIPT_DIR / "html" / "generate_html_dashboard.py"

if __name__ == "__main__":
    runpy.run_path(str(TARGET), run_name="__main__")
