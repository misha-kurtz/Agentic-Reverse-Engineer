"""
Real CDB integration test: VirtualProtect + hardware execution breakpoint.

Validates:
    1. Real CDB initialization
    2. VirtualProtect API breakpoint installation
    3. Hardware execution breakpoint installation
    4. Selective VirtualProtect disabling
    5. Hardware breakpoint preservation
    6. VirtualProtect gu return behavior
    7. Selective VirtualProtect re-enabling
    8. Hardware execution breakpoint triggering
    9. HYP_OEP event classification
   10. Final RIP verification

Run:
    python virtual-protect-oep-debugger-integration-test.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
CDB_PATH = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")
TEST_EXECUTABLE = PROJECT_ROOT / "virtual-protect-oep-test-target.exe"

sys.path.insert(0, str(PROJECT_ROOT))

from runners.debugger import CdbDebugger
from workflows.payload_recovery.runtime_decrypt import RuntimeDecryptor


def parse_breakpoints(output: str) -> dict[int, dict]:
    breakpoints = {}

    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+([ed])\s+", line)

        if match:
            breakpoint_id = int(match.group(1))
            breakpoints[breakpoint_id] = {
                "enabled": match.group(2) == "e",
                "line": line.strip()
            }

    return breakpoints


class VirtualProtectOEPIntegrationTest:
    def __init__(self):
        self.debugger = CdbDebugger(cdb_path=CDB_PATH, command_timeout=30.0)
        self.decryptor = RuntimeDecryptor(debugger=self.debugger)
        self.protect_id = None
        self.oep_id = None
        self.oep_va = None

    def show_breakpoints(self) -> dict[int, dict]:
        output = self.debugger.command("bl")
        print("\n[CDB BREAKPOINTS]")
        print(output)
        return parse_breakpoints(output)

    def assert_breakpoint_enabled(self, breakpoint_id: int, enabled: bool) -> None:
        breakpoints = self.show_breakpoints()

        if breakpoint_id not in breakpoints:
            raise AssertionError(f"Breakpoint ID {breakpoint_id} is missing")

        actual = breakpoints[breakpoint_id]["enabled"]

        if actual != enabled:
            raise AssertionError(f"Breakpoint {breakpoint_id}: expected enabled={enabled}, got {actual}")

        print(f"[PASS] Breakpoint {breakpoint_id} enabled={enabled}")

    def launch(self) -> None:
        print("\n=== TEST 1: LAUNCH CDB ===")
        self.debugger.launch(TEST_EXECUTABLE)
        self.decryptor._clear_all_breakpoints()
        print("[PASS] CDB launched")

    def install_virtualprotect(self) -> None:
        print("\n=== TEST 2: INSTALL VirtualProtect BREAKPOINT ===")

        self.decryptor._set_api_breakpoint("VirtualProtect")
        self.protect_id = self.decryptor._api_breakpoint_ids["VirtualProtect"]

        self.assert_breakpoint_enabled(self.protect_id, True)
        print(f"[PASS] VirtualProtect ID={self.protect_id}")

    def resolve_oep_target(self) -> None:
        print("\n=== TEST 3: RESOLVE HARDWARE BREAKPOINT TARGET ===")

        output = self.debugger.command("x virtual_protect_oep_test_target!*OEPTestTarget*")
        print(output)

        matches = re.findall(r"(?m)^\s*([0-9a-fA-F`]+)\s+.*OEPTestTarget", output)

        if not matches:
            raise AssertionError(
                "Could not resolve OEPTestTarget symbol. "
                "Ensure the executable was compiled with /Zi /DEBUG.\n" + output
            )

        self.oep_va = int(matches[0].replace("`", ""), 16)
        print(f"[PASS] OEPTestTarget resolved: 0x{self.oep_va:X}")

    def install_hardware_breakpoint(self) -> None:
        print("\n=== TEST 4: INSTALL HARDWARE BREAKPOINT ===")

        before = self.show_breakpoints()

        command = f'ba e1 0x{self.oep_va:X} ".echo HYP_OEP"'
        print(f"[INFO] Installing hardware breakpoint: {command}")

        output = self.debugger.command(command)
        print(f"[INFO] CDB response:\n{output}")

        after = self.show_breakpoints()
        new_ids = set(after) - set(before)

        if len(new_ids) != 1:
            raise AssertionError(f"Expected one new hardware breakpoint, found {new_ids}.\n{output}")

        self.oep_id = new_ids.pop()
        self.assert_breakpoint_enabled(self.oep_id, True)

        if not re.search(r"\be\s+1\b", after[self.oep_id]["line"]):
            raise AssertionError("New breakpoint does not appear to be a hardware execution breakpoint")

        print(f"[PASS] Hardware breakpoint ID={self.oep_id}")

    def wait_for_virtualprotect(self) -> None:
        print("\n=== TEST 5: WAIT FOR VirtualProtect ===")

        for attempt in range(20):
            output = self.debugger.continue_execution()
            event = self.decryptor._classify_event(output)

            print(f"[EVENT {attempt + 1}] {event}")

            if event == "OEP":
                raise AssertionError("OEP target triggered before VirtualProtect return")

            if event == "VirtualProtect":
                print("[PASS] VirtualProtect breakpoint triggered")
                return

            raise AssertionError(f"Unexpected debugger stop:\n{output}")

        raise AssertionError("VirtualProtect breakpoint was not reached")

    def capture_virtualprotect(self):
        print("\n=== TEST 6: CAPTURE VirtualProtect ARGUMENTS ===")

        request = self.decryptor._capture_virtual_protect()

        print(f"Address:        0x{request.address:X}")
        print(f"Size:           0x{request.size:X}")
        print(f"Protection:     0x{request.new_protection:X}")
        print(f"Return address: 0x{request.return_address:X}")

        if request.return_address == 0:
            raise AssertionError("Invalid VirtualProtect return address")

        print("[PASS] VirtualProtect arguments captured")
        return request

    def test_gu_return(self, request) -> None:
        print("\n=== TEST 7: DISABLE VirtualProtect + gu ===")

        self.decryptor._disable_api_breakpoint("VirtualProtect")
        self.assert_breakpoint_enabled(self.protect_id, False)
        self.assert_breakpoint_enabled(self.oep_id, True)

        print("[INFO] Executing gu...")
        output = self.debugger.command("gu", timeout=120.0)
        print(output)

        actual_rip = self.debugger.get_register("rip")

        print(f"Expected RIP: 0x{request.return_address:X}")
        print(f"Actual RIP:   0x{actual_rip:X}")

        if actual_rip != request.return_address:
            raise AssertionError(f"gu returned to unexpected RIP 0x{actual_rip:X}")

        print("[PASS] gu returned to expected caller")

        rax = self.debugger.get_register("rax")
        print(f"[INFO] RAX=0x{rax:X}")

        if rax == 0:
            raise AssertionError("VirtualProtect returned failure")

        print("[PASS] VirtualProtect succeeded")

    def reenable_virtualprotect(self) -> None:
        print("\n=== TEST 8: RE-ENABLE VirtualProtect ===")

        self.decryptor._enable_api_breakpoint("VirtualProtect")
        self.assert_breakpoint_enabled(self.protect_id, True)
        self.assert_breakpoint_enabled(self.oep_id, True)

        print("[PASS] Both breakpoints enabled")

    def trigger_hardware_breakpoint(self) -> None:
        print("\n=== TEST 9: TRIGGER HARDWARE BREAKPOINT ===")

        for attempt in range(50):
            output = self.debugger.continue_execution()
            event = self.decryptor._classify_event(output)

            print(f"[EVENT {attempt + 1}] {event}")

            if event == "OEP":
                actual_rip = self.debugger.get_register("rip")

                print(f"Expected OEP RIP: 0x{self.oep_va:X}")
                print(f"Actual RIP:       0x{actual_rip:X}")

                if actual_rip != self.oep_va:
                    raise AssertionError("OEP event triggered at incorrect address")

                print("[PASS] Hardware execution breakpoint triggered")
                print("[PASS] HYP_OEP marker classified correctly")
                print("[PASS] RIP matches expected target")
                return

            if event == "VirtualProtect":
                request = self.decryptor._capture_virtual_protect()
                self.test_gu_return(request)
                self.reenable_virtualprotect()
                continue

            raise AssertionError(f"Unexpected debugger stop:\n{output}")

        raise AssertionError("Hardware execution breakpoint not reached within 50 events")

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
            self.install_virtualprotect()
            self.resolve_oep_target()

            # Advance beyond the initial process breakpoint.
            self.wait_for_virtualprotect()

            # Hardware breakpoints can now be installed.
            self.install_hardware_breakpoint()

            request = self.capture_virtualprotect()
            self.test_gu_return(request)
            self.reenable_virtualprotect()
            self.trigger_hardware_breakpoint()

            print("\n==========================================")
            print("SUCCESS: Combined VirtualProtect/OEP test passed")
            print("==========================================")
        finally:
            self.cleanup()

def main() -> None:
    if not CDB_PATH.is_file():
        raise FileNotFoundError(f"CDB not found: {CDB_PATH}")

    if not TEST_EXECUTABLE.is_file():
        raise FileNotFoundError(f"Test executable not found: {TEST_EXECUTABLE}")

    test = VirtualProtectOEPIntegrationTest()
    test.run()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\n[FAIL] {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)