"""
Real CDB breakpoint tracking integration test.

Tests RuntimeDecryptor against an actual CdbDebugger instance.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


# ============================================================
# PATH CONFIGURATION
# ============================================================

# Project root: binary-eval/
PROJECT_ROOT = Path(__file__).resolve().parent

# Actual Windows Debugging Tools installation.
CDB_PATH = Path(
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
)

# Use a trusted executable for initial integration testing.
TEST_EXECUTABLE = Path(
    r"C:\Windows\System32\notepad.exe"
)

# Add project root to Python's import search path.
sys.path.insert(
    0,
    str(PROJECT_ROOT),
)


# ============================================================
# PROJECT IMPORTS
# ============================================================

from runners.debugger import CdbDebugger

from workflows.payload_recovery.runtime_decrypt import (
    RuntimeDecryptor,
)


# ============================================================
# PATH VALIDATION
# ============================================================

def validate_paths() -> None:

    print("\n[CONFIG] Project root:")
    print(f"         {PROJECT_ROOT}")

    print("\n[CONFIG] CDB executable:")
    print(f"         {CDB_PATH}")

    print("\n[CONFIG] Test executable:")
    print(f"         {TEST_EXECUTABLE}")

    if not CDB_PATH.is_file():
        raise FileNotFoundError(
            f"CDB executable not found: {CDB_PATH}"
        )

    if not TEST_EXECUTABLE.is_file():
        raise FileNotFoundError(
            f"Test executable not found: {TEST_EXECUTABLE}"
        )

    print("\n[PASS] All configured paths exist.")