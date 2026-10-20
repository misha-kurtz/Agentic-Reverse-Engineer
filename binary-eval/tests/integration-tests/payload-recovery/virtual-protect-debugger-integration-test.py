"""
Real CDB integration test for VirtualProtect return handling.

Validates:
    - API breakpoint installation
    - VirtualProtect argument capture
    - Selective breakpoint disabling
    - CDB gu return behavior
    - Return address verification
    - VirtualProtect return value
    - Breakpoint re-enabling
    - Breakpoint registry consistency

Requires:
    - Windows x64
    - Windows Debugging Tools (CDB)
    - Compiled virtual-protect-test-target.exe

Run:
    python virtual-protect-debugger-integration-test.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
CDB_PATH = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")
TEST_EXECUTABLE = PROJECT_ROOT / "virtual-protect-test-target.exe"

sys.path.insert(0, str(PROJECT_ROOT))

from runners.debugger import CdbDebugger
from workflows.payload_recovery.runtime_decrypt import RuntimeDecryptor


def validate_paths() -> None:
    print("\n=== PATH CONFIGURATION ===")
    print(f"Project root: {PROJECT_ROOT}")
    print(f"CDB: {CDB_PATH}")
    print(f"Target: {TEST_EXECUTABLE}")

    if not CDB_PATH.is_file():
        raise FileNotFoundError(f"CDB not found: {CDB_PATH}")

    if not TEST_EXECUTABLE.is_file():
        raise FileNotFoundError(f"Test executable not found: {TEST_EXECUTABLE}")

    print("[PASS] Paths validated")


def parse_breakpoint_state(output: str, breakpoint_id: int) -> str | None:
    pattern = rf"(?m)^\s*{breakpoint_id}\s+([ed])\b"
    match = re.search(pattern, output)
    return match.group(1) if match else None


class VirtualProtectIntegrationTest:
    def __init__(self):
        self.debugger = CdbDebugger(cdb_path=CDB_PATH, command_timeout=30.0)
        self.decryptor = RuntimeDecryptor(debugger=self.debugger)
        self.protect_id = None

    def assert_breakpoint_state(self, expected: str) -> None:
        output = self.debugger.command("bl")
        state = parse_breakpoint_state(output, self.protect_id)

        if state != expected:
            raise AssertionError(
                f"Expected breakpoint {self.protect_id} state '{expected}', "
                f"got '{state}'.\n{output}"
            )

        print(f"[PASS] VirtualProtect breakpoint state: {state}")

    def launch(self) -> None:
        print("\n=== TEST 1: LAUNCH CDB ===")
        self.debugger.launch(TEST_EXECUTABLE)
        self.decryptor._clear_all_breakpoints()
        print("[PASS] Debugger launched")

    def install_breakpoint(self) -> None:
        print("\n=== TEST 2: INSTALL VirtualProtect BREAKPOINT ===")
        self.decryptor._set_api_breakpoint("VirtualProtect")
        self.protect_id = self.decryptor._api_breakpoint_ids["VirtualProtect"]

        self.assert_breakpoint_state("e")
        print(f"[PASS] VirtualProtect breakpoint ID: {self.protect_id}")

    def wait_for_virtualprotect(self) -> None:
        print("\n=== TEST 3: WAIT FOR VirtualProtect ===")

        output = self.debugger.continue_execution()
        event = self.decryptor._classify_event(output)

        if event != "VirtualProtect":
            raise AssertionError(f"Expected VirtualProtect event, got {event}.\n{output}")

        print("[PASS] VirtualProtect breakpoint triggered")
        print(f"[INFO] RIP: 0x{self.debugger.get_register('rip'):X}")

    def capture_arguments(self):
        print("\n=== TEST 4: CAPTURE ARGUMENTS ===")

        request = self.decryptor._capture_virtual_protect()

        print(f"lpAddress:      0x{request.address:X}")
        print(f"dwSize:         0x{request.size:X}")
        print(f"flNewProtect:   0x{request.new_protection:X}")
        print(f"Return address: 0x{request.return_address:X}")

        assert request.address != 0, "VirtualProtect address is zero"
        assert request.size > 0, "VirtualProtect size is zero"
        assert request.new_protection == 0x02, (
            f"Expected PAGE_READONLY (0x02), got 0x{request.new_protection:X}"
        )
        assert request.return_address != 0, "Return address is zero"

        print("[PASS] VirtualProtect arguments captured")
        return request

    def test_gu_return(self, request) -> None:
        print("\n=== TEST 5: SELECTIVE DISABLE + gu ===")

        self.decryptor._disable_api_breakpoint("VirtualProtect")
        self.assert_breakpoint_state("d")

        print("[INFO] Executing gu...")
        output = self.debugger.command("gu", timeout=120.0)

        print("[INFO] CDB output:")
        print(output)

        actual_rip = self.debugger.get_register("rip")

        print(f"Expected return RIP: 0x{request.return_address:X}")
        print(f"Actual RIP:          0x{actual_rip:X}")

        if actual_rip != request.return_address:
            raise AssertionError(
                f"gu stopped at unexpected address. "
                f"Expected 0x{request.return_address:X}, got 0x{actual_rip:X}.\n{output}"
            )

        print("[PASS] gu returned to the expected caller")

        rax = self.debugger.get_register("rax")
        print(f"[INFO] RAX: 0x{rax:X}")

        if rax == 0:
            raise AssertionError("VirtualProtect returned failure (RAX == 0)")

        print("[PASS] VirtualProtect returned success")

    def reenable_breakpoint(self) -> None:
        print("\n=== TEST 6: RE-ENABLE BREAKPOINT ===")

        self.decryptor._enable_api_breakpoint("VirtualProtect")
        self.assert_breakpoint_state("e")

        assert self.decryptor._api_breakpoint_ids["VirtualProtect"] == self.protect_id
        print("[PASS] Original breakpoint ID preserved")

    def cleanup(self) -> None:
        print("\n=== CLEANUP ===")

        try:
            self.decryptor._clear_all_breakpoints()
            print("[PASS] Breakpoints cleared")
        finally:
            self.debugger.close()
            print("[PASS] Debugger closed")

    def run(self) -> None:
        try:
            self.launch()
            self.install_breakpoint()
            self.wait_for_virtualprotect()
            request = self.capture_arguments()
            self.test_gu_return(request)
            self.reenable_breakpoint()

            print("\n==========================================")
            print("SUCCESS: VirtualProtect integration passed")
            print("==========================================")
        finally:
            self.cleanup()


def main() -> None:
    validate_paths()
    test = VirtualProtectIntegrationTest()
    test.run()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\n[FAIL] {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)