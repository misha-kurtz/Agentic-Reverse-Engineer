"""
breakpoint_tracking_integration_test.py

Real CDB integration tests for RuntimeDecryptor breakpoint tracking.

This script uses the actual CdbDebugger implementation rather than
a mock debugger.

Tests:
    1. Debugger initialization
    2. API breakpoint ID discovery
    3. Multiple API breakpoint registration
    4. Hardware execution breakpoint installation
    5. Selective API breakpoint disabling
    6. Selective API breakpoint enabling
    7. Selective API breakpoint removal
    8. Breakpoint registry cleanup

The debugger launches a trusted executable and remains paused at
its initial debugger break.

No commands intentionally resume target execution.

Run:
    python breakpoint_tracking_integration_test.py
"""

from __future__ import annotations

import re
import sys

from pathlib import Path


# ============================================================
# PATH CONFIGURATION
# ============================================================

# Expected project structure:
#
# binary-eval/
# ├── breakpoint_tracking_integration_test.py
# ├── runners/
# │   └── debugger.py
# └── workflows/
#     └── payload_recovery/
#         └── runtime_decrypt.py


# Automatically determine the project root.
PROJECT_ROOT = Path(__file__).resolve().parent


# Windows Debugging Tools installation.
#
# Change this path if CDB is installed elsewhere.

CDB_PATH = Path(
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
)


# Trusted executable used for integration testing.
#
# Do not use enc.exe for this initial breakpoint test.

TEST_EXECUTABLE = Path(
    r"C:\Windows\System32\notepad.exe"
)


# Add the project root to Python's import path.

sys.path.insert(
    0,
    str(PROJECT_ROOT),
)


# ============================================================
# PROJECT IMPORTS
# ============================================================

from runners.debugger import (
    CdbDebugger,
)

from workflows.payload_recovery.runtime_decrypt import (
    RuntimeDecryptor,
)


# ============================================================
# PATH VALIDATION
# ============================================================

def validate_paths() -> None:

    print(
        "\n=========================================="
    )

    print(
        "PATH CONFIGURATION"
    )

    print(
        "=========================================="
    )

    print(
        f"\n[CONFIG] Project root:\n{PROJECT_ROOT}"
    )

    print(
        f"\n[CONFIG] CDB executable:\n{CDB_PATH}"
    )

    print(
        f"\n[CONFIG] Test executable:\n{TEST_EXECUTABLE}"
    )

    if not PROJECT_ROOT.is_dir():

        raise FileNotFoundError(
            f"Project root not found: {PROJECT_ROOT}"
        )

    if not CDB_PATH.is_file():

        raise FileNotFoundError(
            f"CDB executable not found: {CDB_PATH}"
        )

    if not TEST_EXECUTABLE.is_file():

        raise FileNotFoundError(
            f"Test executable not found: {TEST_EXECUTABLE}"
        )

    debugger_module = (
        PROJECT_ROOT
        / "runners"
        / "debugger.py"
    )

    decryptor_module = (
        PROJECT_ROOT
        / "workflows"
        / "payload_recovery"
        / "runtime_decrypt.py"
    )

    if not debugger_module.is_file():

        raise FileNotFoundError(
            f"Debugger module not found: {debugger_module}"
        )

    if not decryptor_module.is_file():

        raise FileNotFoundError(
            f"RuntimeDecryptor module not found: {decryptor_module}"
        )

    print(
        "\n[PASS] All configured paths exist."
    )


# ============================================================
# CDB OUTPUT VALIDATION
# ============================================================

ERROR_PATTERNS = (
    r"(?i)\bsyntax error\b",
    r"(?i)\bcommand error\b",
    r"(?i)\bunknown command\b",
    r"(?i)\bcouldn't resolve\b",
    r"(?i)\bunable to resolve\b",
    r"(?i)\binvalid breakpoint\b",
    r"(?i)\bno such breakpoint\b",
)


def assert_no_cdb_errors(
    output: str,
    operation: str,
) -> None:

    for pattern in ERROR_PATTERNS:

        if re.search(
            pattern,
            output,
        ):

            raise AssertionError(
                f"CDB reported an error during {operation}:\n"
                f"{output}"
            )


# ============================================================
# BREAKPOINT LISTING PARSER
# ============================================================

def parse_breakpoints(
    output: str,
) -> dict[int, dict]:

    """
    Parse breakpoint IDs and enabled states from CDB's
    breakpoint listing.

    Typical CDB breakpoint entries begin with:

        0 e ...
        1 d ...

    e = enabled
    d = disabled

    Only the breakpoint ID and state are extracted.
    """

    breakpoints = {}

    pattern = re.compile(
        r"^\s*(\d+)\s+([ed])\b",
        re.MULTILINE,
    )

    for match in pattern.finditer(output):

        breakpoint_id = int(
            match.group(1),
            10,
        )

        enabled = (
            match.group(2) == "e"
        )

        breakpoints[breakpoint_id] = {
            "enabled": enabled,
        }

    return breakpoints


# ============================================================
# INTEGRATION TEST RUNNER
# ============================================================

class BreakpointIntegrationTest:

    def __init__(
        self,
        cdb_path: Path,
        executable: Path,
    ):

        self.cdb_path = cdb_path

        self.executable = executable

        # Actual debugger instance.
        self.debugger = CdbDebugger(
            cdb_path=self.cdb_path,
            command_timeout=30.0,
        )

        # Create RuntimeDecryptor without assuming its constructor
        # accepts a debugger keyword argument.
        #
        # This test needs only its breakpoint-management methods
        # and the actual CDB instance.
        #
        # __new__ bypasses normal workflow initialization.
        # It is appropriate here because this is a narrowly
        # scoped breakpoint integration test.

        self.decryptor = RuntimeDecryptor.__new__(
            RuntimeDecryptor
        )

        self.decryptor.debugger = self.debugger

        self.decryptor._api_breakpoint_ids = {}

        self.hardware_breakpoint_id = None

    # ========================================================
    # HELPERS
    # ========================================================

    def command(
        self,
        command: str,
    ) -> str:

        print(
            f"\n[CDB COMMAND] {command}"
        )

        output = self.debugger.command(
            command
        )

        assert_no_cdb_errors(
            output,
            command,
        )

        return output

    def list_breakpoints(
        self,
    ) -> dict[int, dict]:

        output = self.command(
            "bl"
        )

        print(
            "\n[CDB BREAKPOINT LIST]"
        )

        print(
            output
        )

        return parse_breakpoints(
            output
        )

    def assert_state(
        self,
        breakpoint_id: int,
        enabled: bool,
    ) -> None:

        breakpoints = self.list_breakpoints()

        assert breakpoint_id in breakpoints, (
            f"Breakpoint {breakpoint_id} is missing."
        )

        actual = breakpoints[
            breakpoint_id
        ]["enabled"]

        assert actual == enabled, (
            f"Breakpoint {breakpoint_id}: "
            f"expected enabled={enabled}, "
            f"actual enabled={actual}"
        )

    def assert_preserved(
        self,
        breakpoint_id: int,
    ) -> None:

        self.assert_state(
            breakpoint_id,
            enabled=True,
        )

    def print_pass(
        self,
        message: str,
    ) -> None:

        print(
            f"\n[PASS] {message}"
        )

    # ========================================================
    # TEST 1: LAUNCH DEBUGGER
    # ========================================================

    def launch(
        self,
    ) -> None:

        print(
            "\n=========================================="
        )

        print(
            "TEST 1: Launch real CDB debugger"
        )

        print(
            "=========================================="
        )

        print(
            f"\nCDB: {self.cdb_path}"
        )

        print(
            f"Target: {self.executable}"
        )

        self.debugger.launch(
            self.executable
        )

        print(
            "\n[INFO] CDB stopped at initial debugger break."
        )

        # Begin with an empty breakpoint table.

        self.decryptor._clear_all_breakpoints()

        breakpoints = self.list_breakpoints()

        assert not breakpoints, (
            "Expected no breakpoints after initial cleanup."
        )

        self.print_pass(
            "Debugger launched and breakpoint table cleared"
        )

    # ========================================================
    # TEST 2: API BREAKPOINT DISCOVERY
    # ========================================================

    def test_breakpoint_discovery(
        self,
    ) -> int:

        print(
            "\n=========================================="
        )

        print(
            "TEST 2: API breakpoint ID discovery"
        )

        print(
            "=========================================="
        )

        self.decryptor._set_api_breakpoint(
            "VirtualProtect"
        )

        breakpoint_id = (
            self.decryptor._find_api_breakpoint_id(
                "VirtualProtect"
            )
        )

        registered_id = (
            self.decryptor._api_breakpoint_ids[
                "VirtualProtect"
            ]
        )

        assert breakpoint_id == registered_id, (
            "Discovered breakpoint ID does not match registry."
        )

        self.assert_state(
            breakpoint_id,
            enabled=True,
        )

        self.print_pass(
            f"VirtualProtect registered as ID={breakpoint_id}"
        )

        return breakpoint_id

    # ========================================================
    # TEST 3: MULTIPLE API BREAKPOINTS
    # ========================================================

    def test_multiple_breakpoints(
        self,
        protect_id: int,
    ) -> int:

        print(
            "\n=========================================="
        )

        print(
            "TEST 3: Independent API breakpoint IDs"
        )

        print(
            "=========================================="
        )

        self.decryptor._set_api_breakpoint(
            "VirtualAlloc"
        )

        alloc_id = (
            self.decryptor._api_breakpoint_ids[
                "VirtualAlloc"
            ]
        )

        assert alloc_id != protect_id, (
            "VirtualAlloc and VirtualProtect share an ID."
        )

        self.assert_state(
            protect_id,
            enabled=True,
        )

        self.assert_state(
            alloc_id,
            enabled=True,
        )

        self.print_pass(
            "VirtualProtect and VirtualAlloc have distinct IDs"
        )

        return alloc_id

    # ========================================================
    # TEST 4: HARDWARE EXECUTION BREAKPOINT
    # ========================================================

    def test_hardware_breakpoint(
        self,
    ) -> int:

        print(
            "\n=========================================="
        )

        print(
            "TEST 4: Hardware execution breakpoint"
        )

        print(
            "=========================================="
        )

        # Capture the current instruction pointer.
        #
        # The target is paused at CDB's initial break.
        #
        # We use this address as the test location for a
        # hardware execution breakpoint.

        rip = self.debugger.get_register(
            "rip"
        )

        print(
            f"\n[INFO] Current RIP: 0x{rip:X}"
        )

        before = self.list_breakpoints()

        # Install hardware execution breakpoint.
        #
        # ba e1 = break on instruction execution.

        self.command(
            f'ba e1 0x{rip:X} ".echo HYP_OEP_TEST"'
        )

        output = self.command(
            "bl"
        )

        print(
            "\n[CDB BREAKPOINT LIST]"
        )

        print(
            output
        )

        after = parse_breakpoints(
            output
        )

        new_ids = (
            set(after.keys())
            - set(before.keys())
        )

        assert len(new_ids) == 1, (
            "Expected exactly one new hardware breakpoint. "
            f"Found IDs: {sorted(new_ids)}"
        )

        hardware_id = new_ids.pop()

        self.assert_state(
            hardware_id,
            enabled=True,
        )

        self.hardware_breakpoint_id = (
            hardware_id
        )

        self.print_pass(
            f"Hardware execution breakpoint installed "
            f"as ID={hardware_id}"
        )

        return hardware_id

    # ========================================================
    # TEST 5: SELECTIVE DISABLING
    # ========================================================

    def test_selective_disable(
        self,
        protect_id: int,
        alloc_id: int,
        hardware_id: int,
    ) -> None:

        print(
            "\n=========================================="
        )

        print(
            "TEST 5: Selective breakpoint disabling"
        )

        print(
            "=========================================="
        )

        self.decryptor._disable_api_breakpoint(
            "VirtualProtect"
        )

        self.assert_state(
            protect_id,
            enabled=False,
        )

        self.assert_state(
            alloc_id,
            enabled=True,
        )

        self.assert_preserved(
            hardware_id
        )

        self.print_pass(
            "bd disabled only VirtualProtect"
        )

        self.print_pass(
            "VirtualAlloc remained enabled"
        )

        self.print_pass(
            "Hardware execution breakpoint remained enabled"
        )

    # ========================================================
    # TEST 6: SELECTIVE ENABLING
    # ========================================================

    def test_selective_enable(
        self,
        protect_id: int,
        alloc_id: int,
        hardware_id: int,
    ) -> None:

        print(
            "\n=========================================="
        )

        print(
            "TEST 6: Selective breakpoint enabling"
        )

        print(
            "=========================================="
        )

        self.decryptor._enable_api_breakpoint(
            "VirtualProtect"
        )

        self.assert_state(
            protect_id,
            enabled=True,
        )

        self.assert_state(
            alloc_id,
            enabled=True,
        )

        self.assert_preserved(
            hardware_id
        )

        self.print_pass(
            "be re-enabled VirtualProtect"
        )

        self.print_pass(
            "Other breakpoints remained enabled"
        )

    # ========================================================
    # TEST 7: SELECTIVE REMOVAL
    # ========================================================

    def test_selective_remove(
        self,
        protect_id: int,
        alloc_id: int,
        hardware_id: int,
    ) -> None:

        print(
            "\n=========================================="
        )

        print(
            "TEST 7: Selective breakpoint removal"
        )

        print(
            "=========================================="
        )

        self.decryptor._remove_api_breakpoint(
            "VirtualProtect"
        )

        breakpoints = self.list_breakpoints()

        assert protect_id not in breakpoints, (
            "VirtualProtect breakpoint still exists."
        )

        assert alloc_id in breakpoints, (
            "VirtualAlloc breakpoint was unexpectedly removed."
        )

        assert hardware_id in breakpoints, (
            "Hardware breakpoint was unexpectedly removed."
        )

        assert (
            "VirtualProtect"
            not in self.decryptor._api_breakpoint_ids
        ), (
            "VirtualProtect remains in registry."
        )

        self.assert_preserved(
            hardware_id
        )

        self.print_pass(
            "bc removed only VirtualProtect"
        )

        self.print_pass(
            "VirtualAlloc and hardware breakpoints survived"
        )

        self.print_pass(
            "VirtualProtect registry entry removed"
        )

    # ========================================================
    # TEST 8: CLEAR ALL BREAKPOINTS
    # ========================================================

    def test_clear_all(
        self,
    ) -> None:

        print(
            "\n=========================================="
        )

        print(
            "TEST 8: Clear all breakpoints"
        )

        print(
            "=========================================="
        )

        self.decryptor._clear_all_breakpoints()

        breakpoints = self.list_breakpoints()

        assert not breakpoints, (
            "CDB still contains breakpoints after bc *."
        )

        assert (
            self.decryptor._api_breakpoint_ids == {}
        ), (
            "API breakpoint registry was not cleared."
        )

        self.print_pass(
            "bc * cleared all CDB breakpoints"
        )

        self.print_pass(
            "Python API breakpoint registry cleared"
        )

    # ========================================================
    # MAIN TEST SEQUENCE
    # ========================================================

    def run(
        self,
    ) -> None:

        try:

            self.launch()

            protect_id = (
                self.test_breakpoint_discovery()
            )

            alloc_id = (
                self.test_multiple_breakpoints(
                    protect_id
                )
            )

            hardware_id = (
                self.test_hardware_breakpoint()
            )

            self.test_selective_disable(
                protect_id,
                alloc_id,
                hardware_id,
            )

            self.test_selective_enable(
                protect_id,
                alloc_id,
                hardware_id,
            )

            self.test_selective_remove(
                protect_id,
                alloc_id,
                hardware_id,
            )

            self.test_clear_all()

            print(
                "\n=========================================="
            )

            print(
                "SUCCESS"
            )

            print(
                "Real CDB breakpoint tracking tests passed."
            )

            print(
                "=========================================="
            )

        finally:

            print(
                "\n[cleanup] Closing CDB debugger."
            )

            self.debugger.close()


# ============================================================
# MAIN
# ============================================================

def main(
) -> None:

    validate_paths()

    test = BreakpointIntegrationTest(
        cdb_path=CDB_PATH,
        executable=TEST_EXECUTABLE,
    )

    test.run()


if __name__ == "__main__":

    try:

        main()

    except Exception as exc:

        print(
            f"\n[FAIL] {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )

        sys.exit(1)