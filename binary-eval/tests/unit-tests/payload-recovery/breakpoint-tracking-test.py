"""
test_breakpoint_tracking.py

Unit tests for RuntimeDecryptor breakpoint ID tracking.

Tests:
    1. API breakpoint ID discovery
    2. Selective breakpoint disabling
    3. Selective breakpoint enabling
    4. Registry cleanup
    5. Debugger command errors
    6. Preservation of unrelated OEP breakpoints

Does not launch or execute a target executable.
"""

import re
import sys
import unittest

from pathlib import Path
from unittest.mock import MagicMock


# ------------------------------------------------------------
# Import project module
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(
    0,
    str(PROJECT_ROOT),
)

from workflows.payload_recovery.runtime_decrypt import (
    RuntimeDecryptor,
    RuntimeDecryptError,
)


# ------------------------------------------------------------
# Mock CDB debugger
# ------------------------------------------------------------

class MockCdbDebugger:
    """
    Simulate the subset of CDB breakpoint commands used by
    RuntimeDecryptor.

    Supported commands:

        bu KERNELBASE!API ".echo MARKER"
        bl
        bd <id>
        be <id>
        bc <id>

    A hardware OEP breakpoint is preinstalled with ID 7.

    This is a test double, not an implementation of CDB.
    """

    def __init__(self):

        self.breakpoints = {
            7: {
                "symbol": "OEP",
                "marker": "HYP_OEP",
                "enabled": True,
                "hardware": True,
            }
        }

        self.next_breakpoint_id = 8

        self.command_history = []

        self.errors = []

    def command(self, command, **kwargs):

        self.command_history.append(command)

        command = command.strip()

        # ----------------------------------------------------
        # List breakpoints
        # ----------------------------------------------------

        if command == "bl":

            lines = []

            for breakpoint_id, breakpoint in sorted(
                self.breakpoints.items()
            ):

                state = (
                    "e"
                    if breakpoint["enabled"]
                    else "d"
                )

                lines.append(
                    f"{breakpoint_id} {state} "
                    f"Disable Clear "
                    f"00000000`00000000 "
                    f"0001 (0001) "
                    f"{breakpoint['symbol']} "
                    f'".echo {breakpoint["marker"]}"'
                )

            return "\n".join(lines)

        # ----------------------------------------------------
        # Install API breakpoint
        # ----------------------------------------------------

        if command.startswith("bu "):

            match = re.match(
                r'^bu\s+'
                r'(KERNELBASE![A-Za-z0-9_]+)\s+'
                r'"\.echo\s+([A-Za-z0-9_]+)"$',
                command,
            )

            if match is None:
                return self._error(
                    f"Invalid breakpoint command: {command}"
                )

            symbol = match.group(1)
            marker = match.group(2)

            breakpoint_id = self.next_breakpoint_id

            self.next_breakpoint_id += 1

            self.breakpoints[breakpoint_id] = {
                "symbol": symbol,
                "marker": marker,
                "enabled": True,
                "hardware": False,
            }

            return ""

        # ----------------------------------------------------
        # Disable / enable / clear breakpoint
        # ----------------------------------------------------

        match = re.fullmatch(
            r"(bd|be|bc)\s+(\d+)",
            command,
        )

        if match:

            operation = match.group(1)
            breakpoint_id = int(match.group(2))

            if breakpoint_id not in self.breakpoints:

                return self._error(
                    f"Breakpoint {breakpoint_id} does not exist"
                )

            if operation == "bd":

                self.breakpoints[breakpoint_id][
                    "enabled"
                ] = False

            elif operation == "be":

                self.breakpoints[breakpoint_id][
                    "enabled"
                ] = True

            elif operation == "bc":

                del self.breakpoints[breakpoint_id]

            return ""

        return self._error(
            f"Unsupported debugger command: {command}"
        )

    def clear_all_breakpoints(self):

        self.breakpoints.clear()

    def _error(self, message):

        self.errors.append(message)

        return f"error: {message}"


# ------------------------------------------------------------
# Breakpoint tracking tests
# ------------------------------------------------------------

class TestBreakpointTracking(unittest.TestCase):

    def setUp(self):

        self.debugger = MockCdbDebugger()

        self.decryptor = RuntimeDecryptor(
            debugger=self.debugger
        )

    # --------------------------------------------------------
    # Test 1: Breakpoint ID discovery
    # --------------------------------------------------------

    def test_find_api_breakpoint_id(self):

        self.decryptor._set_api_breakpoint(
            "VirtualProtect"
        )

        breakpoint_id = (
            self.decryptor._find_api_breakpoint_id(
                "VirtualProtect"
            )
        )

        self.assertEqual(
            breakpoint_id,
            8,
        )

        self.assertEqual(
            self.decryptor._api_breakpoint_ids[
                "VirtualProtect"
            ],
            8,
        )

        self.assertEqual(
            self.debugger.breakpoints[8]["symbol"],
            "KERNELBASE!VirtualProtect",
        )

        print(
            "[PASS] Correct API breakpoint ID discovered"
        )

    # --------------------------------------------------------
    # Test 2: Selective disabling
    # --------------------------------------------------------

    def test_disable_only_api_breakpoint(self):

        self.decryptor._set_api_breakpoint(
            "VirtualProtect"
        )

        api_id = self.decryptor._api_breakpoint_ids[
            "VirtualProtect"
        ]

        self.decryptor._disable_api_breakpoint(
            "VirtualProtect"
        )

        self.assertFalse(
            self.debugger.breakpoints[api_id]["enabled"]
        )

        # The unrelated hardware OEP breakpoint must
        # remain installed and enabled.

        self.assertIn(
            7,
            self.debugger.breakpoints,
        )

        self.assertTrue(
            self.debugger.breakpoints[7]["enabled"]
        )

        self.assertTrue(
            self.debugger.breakpoints[7]["hardware"]
        )

        self.assertIn(
            f"bd {api_id}",
            self.debugger.command_history,
        )

        print(
            "[PASS] API breakpoint disabled; OEP preserved"
        )

    # --------------------------------------------------------
    # Test 3: Re-enable breakpoint
    # --------------------------------------------------------

    def test_reenable_api_breakpoint(self):

        self.decryptor._set_api_breakpoint(
            "VirtualProtect"
        )

        api_id = self.decryptor._api_breakpoint_ids[
            "VirtualProtect"
        ]

        self.decryptor._disable_api_breakpoint(
            "VirtualProtect"
        )

        self.decryptor._enable_api_breakpoint(
            "VirtualProtect"
        )

        self.assertTrue(
            self.debugger.breakpoints[api_id]["enabled"]
        )

        self.assertTrue(
            self.debugger.breakpoints[7]["enabled"]
        )

        self.assertIn(
            f"be {api_id}",
            self.debugger.command_history,
        )

        print(
            "[PASS] API breakpoint re-enabled"
        )

    # --------------------------------------------------------
    # Test 4: Registry cleanup
    # --------------------------------------------------------

    def test_clear_all_breakpoints(self):

        self.decryptor._set_api_breakpoint(
            "VirtualProtect"
        )

        self.decryptor._set_api_breakpoint(
            "VirtualAlloc"
        )

        self.assertEqual(
            len(self.decryptor._api_breakpoint_ids),
            2,
        )

        self.decryptor._clear_all_breakpoints()

        self.assertEqual(
            self.decryptor._api_breakpoint_ids,
            {},
        )

        self.assertEqual(
            self.debugger.breakpoints,
            {},
        )

        print(
            "[PASS] Breakpoints and registry cleared"
        )

    # --------------------------------------------------------
    # Test 5: No debugger command errors
    # --------------------------------------------------------

    def test_no_debugger_command_errors(self):

        self.decryptor._set_api_breakpoint(
            "VirtualProtect"
        )

        self.decryptor._disable_api_breakpoint(
            "VirtualProtect"
        )

        self.decryptor._enable_api_breakpoint(
            "VirtualProtect"
        )

        self.decryptor._remove_api_breakpoint(
            "VirtualProtect"
        )

        self.assertEqual(
            self.debugger.errors,
            [],
        )

        self.assertNotIn(
            "VirtualProtect",
            self.decryptor._api_breakpoint_ids,
        )

        self.assertEqual(
            len(self.debugger.breakpoints),
            1,
        )

        self.assertIn(
            7,
            self.debugger.breakpoints,
        )

        print(
            "[PASS] No debugger command errors"
        )

    # --------------------------------------------------------
    # Additional test: Prevent duplicate API breakpoints
    # --------------------------------------------------------

    def test_no_duplicate_breakpoints(self):

        self.decryptor._set_api_breakpoint(
            "VirtualProtect"
        )

        self.decryptor._set_api_breakpoint(
            "VirtualProtect"
        )

        matching = [
            breakpoint
            for breakpoint in self.debugger.breakpoints.values()
            if breakpoint["symbol"]
            == "KERNELBASE!VirtualProtect"
        ]

        self.assertEqual(
            len(matching),
            1,
        )

        print(
            "[PASS] Duplicate API breakpoint prevented"
        )


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

if __name__ == "__main__":

    unittest.main(
        verbosity=2
    )