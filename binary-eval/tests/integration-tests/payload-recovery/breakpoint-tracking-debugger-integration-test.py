"""
breakpoint_tracking_integration_test.py

Integration tests for RuntimeDecryptor breakpoint tracking
using an actual CdbDebugger instance.

Tests:
    1. API breakpoint ID discovery
    2. Multiple API breakpoint registration
    3. Selective breakpoint disabling
    4. Selective breakpoint enabling
    5. Selective breakpoint removal
    6. Hardware breakpoint preservation
    7. Registry cleanup
    8. CDB command error detection

This test does not intentionally continue execution
beyond CDB's initial debugger break.

Run only with a trusted executable in an isolated
analysis environment.
"""

from __future__ import annotations

import argparse
import re
import sys

from pathlib import Path


# ------------------------------------------------------------
# Project imports
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent

sys.path.insert(
    0,
    str(PROJECT_ROOT),
)

from runners.debugger import CdbDebugger

from workflows.payload_recovery.runtime_decrypt import (
    RuntimeDecryptor,
)


# ------------------------------------------------------------
# CDB output validation
# ------------------------------------------------------------

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

        if re.search(pattern, output):

            raise AssertionError(
                f"CDB reported an error during {operation}:\n"
                f"{output}"
            )


# ------------------------------------------------------------
# Breakpoint listing parser
# ------------------------------------------------------------

def parse_breakpoints(
    output: str,
) -> dict[int, dict]:

    """
    Parse breakpoint IDs and enabled states from CDB's
    breakpoint listing.

    Expected breakpoint lines begin with:

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


# ------------------------------------------------------------
# Integration test runner
# ------------------------------------------------------------

class BreakpointIntegrationTest:

    def __init__(
        self,
        cdb_path: Path,
        executable: Path,
    ):

        self.cdb_path = cdb_path

        self.executable = executable

        self.debugger = CdbDebugger(
            cdb_path=self.cdb_path,
            command_timeout=30.0,
        )

        self.decryptor = RuntimeDecryptor(
            debugger=self.debugger,
        )

        self.hardware_breakpoint_id = None

    # --------------------------------------------------------
    # Helpers
    # --------------------------------------------------------

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

    def list_breakpoints(self) -> dict[int, dict]:

        output = self.command("bl")

        print(
            "\n[CDB BREAKPOINT LIST]"
        )

        print(output)

        return parse_breakpoints(output)

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

    # --------------------------------------------------------
    # Test 1: Launch debugger
    # --------------------------------------------------------

    def launch(self) -> None:

        print(
            "\n=========================================="
        )

        print(
            "Launching real CDB debugger"
        )

        print(
            "=========================================="
        )

        print(
            f"CDB: {self.cdb_path}"
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

    # --------------------------------------------------------
    # Test 2: Install VirtualProtect
    # --------------------------------------------------------

    def test_breakpoint_discovery(self) -> int:

        print(
            "\n=========================================="
        )

        print(
            "TEST 1: API breakpoint ID discovery"
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

    # --------------------------------------------------------
    # Test 3: Install second API breakpoint
    # --------------------------------------------------------

    def test_multiple_breakpoints(
        self,
        protect_id: int,
    ) -> int:

        print(
            "\n=========================================="
        )

        print(
            "TEST 2: Independent API breakpoint IDs"
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

    # --------------------------------------------------------
    # Test 4: Install hardware execution breakpoint
    # --------------------------------------------------------

    def test_hardware_breakpoint(
        self,
    ) -> int:

        print(
            "\n=========================================="
        )

        print(
            "TEST 3: Hardware execution breakpoint"
        )

        print(
            "=========================================="
        )

        # Capture current instruction pointer.
        #
        # The target is paused at CDB's initial break.
        #
        # We use this address only as a harmless test
        # location for a hardware execution breakpoint.

        rip = self.debugger.get_register(
            "rip"
        )

        print(
            f"\n[INFO] Current RIP: 0x{rip:X}"
        )

        before = self.list_breakpoints()

        # Install a hardware execution breakpoint.
        #
        # The marker allows identification in CDB's
        # breakpoint listing.

        self.command(
            f'ba e1 0x{rip:X} ".echo HYP_OEP_TEST"'
        )

        output = self.command("bl")

        print(
            "\n[CDB BREAKPOINT LIST]"
        )

        print(output)

        after = parse_breakpoints(output)

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

        self.hardware_breakpoint_id = hardware_id

        self.print_pass(
            f"Hardware execution breakpoint installed "
            f"as ID={hardware_id}"
        )

        return hardware_id

    # --------------------------------------------------------
    # Test 5: Disable only VirtualProtect
    # --------------------------------------------------------

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
            "TEST 4: Selective breakpoint disabling"
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

    # --------------------------------------------------------
    # Test 6: Re-enable VirtualProtect
    # --------------------------------------------------------

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
            "TEST 5: Selective breakpoint enabling"
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

    # --------------------------------------------------------
    # Test 7: Remove only VirtualProtect
    # --------------------------------------------------------

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
            "TEST 6: Selective breakpoint removal"
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

    # --------------------------------------------------------
    # Test 8: Clear all breakpoints
    # --------------------------------------------------------

    def test_clear_all(self) -> None:

        print(
            "\n=========================================="
        )

        print(
            "TEST 7: Clear all breakpoints"
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

    # --------------------------------------------------------
    # Main test sequence
    # --------------------------------------------------------

    def run(self) -> None:

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


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Test RuntimeDecryptor breakpoint tracking "
            "against a real CDB debugger."
        )
    )

    parser.add_argument(
        "--cdb",
        type=Path,
        required=True,
        help="Path to cdb.exe",
    )

    parser.add_argument(
        "--target",
        type=Path,
        required=True,
        help="Path to a trusted Windows test executable",
    )

    args = parser.parse_args()

    if not args.cdb.is_file():

        parser.error(
            f"CDB executable not found: {args.cdb}"
        )

    if not args.target.is_file():

        parser.error(
            f"Test executable not found: {args.target}"
        )

    test = BreakpointIntegrationTest(
        cdb_path=args.cdb,
        executable=args.target,
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