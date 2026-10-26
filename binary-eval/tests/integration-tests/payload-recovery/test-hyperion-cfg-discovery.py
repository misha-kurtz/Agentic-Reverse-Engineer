'''
Integration test for Hyperion CFG-based successful-decryption breakpoint discovery.

Tests:
    1. Launch the encrypted executable under CDB.
    2. Stop at the encrypted entry point.
    3. Monitor Hyperion's API bootstrap and VirtualAlloc.
    4. Identify the initial ciphertext REP MOVSQ.
    5. Complete the initial ciphertext copy.
    6. Discover the successful-decryption breakpoint using CFG analysis.
    7. Verify CFG discovery does not advance execution.
    8. Optionally continue to the successful-decryption breakpoint.
    9. Optionally validate recovered PE metadata.

Modes:
    discovery            Test CFG discovery only.
    decryption-success   Continue to successful-decryption breakpoint and validate PE.
    full                 Execute the existing complete recovery workflow.

Run inside the isolated malware-analysis VM.
'''

import argparse
import traceback
from pathlib import Path

import pefile

from runners.debugger import CdbDebugger
from workflows.payload_recovery.runtime_decrypt import RuntimeDecryptor


# ----------------------------------------------------------
# Configuration
# ----------------------------------------------------------

CDB_PATH = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")

SAMPLES = {
    "bind_shell": {
        "path": Path(r"C:\analysis\bind_shell_enc.exe"),
        "encrypted_entry_rva": 0x4EB50,
        "allocation_size": 0x22010,
        "source_rva": 0x27000,
        "expected_decryption_success_rva": 0x4EAE6,
        "expected_oep_rva": 0x17E0
    },
    "ransomware": {
        "path": Path(r"C:\analysis\ransomware_enc.exe"),
        "encrypted_entry_rva": 0x5FB50,
        "allocation_size": 0x2A210,
        "source_rva": 0x30000,
        "expected_decryption_success_rva": None,
        "expected_oep_rva": 0x3998
    }
}


# ----------------------------------------------------------
# Assertions
# ----------------------------------------------------------

def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)

    print(f"[PASS] {message}")


def check_equal(actual: int, expected: int, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected 0x{expected:X}, got 0x{actual:X}")

    print(f"[PASS] {label}: 0x{actual:X}")


# ----------------------------------------------------------
# Test 1: Encrypted entry point
# ----------------------------------------------------------

def test_encrypted_entry(debugger, decryptor, executable, expected):
    print("\n=== TEST 1: ENCRYPTED ENTRY POINT ===")

    pe = pefile.PE(str(executable))

    try:
        check(pe.OPTIONAL_HEADER.Magic == 0x20B, "Executable is PE32+")
        encrypted_entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    finally:
        pe.close()

    check_equal(encrypted_entry_rva, expected["encrypted_entry_rva"], "Encrypted entry RVA")

    debugger.launch(executable)

    module = debugger.get_module(executable.name)
    image_base = module.base
    entry_va = image_base + encrypted_entry_rva

    debugger.set_breakpoint(entry_va)
    debugger.continue_execution()

    decryptor._require_rip(entry_va)
    decryptor._clear_all_breakpoints()

    check_equal(debugger.get_register("rip"), entry_va, "Encrypted entry RIP")

    return module


# ----------------------------------------------------------
# Test 2: API bootstrap and VirtualAlloc
# ----------------------------------------------------------

def test_bootstrap(decryptor, module, expected):
    print("\n=== TEST 2: API BOOTSTRAP ===")

    events, allocation = decryptor._observe_loader_bootstrap(
        image_base=module.base,
        image_end=module.end
    )

    check(len(events) > 0, "API bootstrap events captured")
    check_equal(allocation.size, expected["allocation_size"], "VirtualAlloc allocation size")
    check(allocation.base != 0, "VirtualAlloc returned a valid allocation")

    print(f"[INFO] Allocation base: 0x{allocation.base:X}")
    print(f"[INFO] Allocation size: 0x{allocation.size:X}")
    print(f"[INFO] Bootstrap events: {len(events)}")

    return allocation


# ----------------------------------------------------------
# Test 3: Initial REP MOVSQ
# ----------------------------------------------------------

def test_initial_copy(debugger, decryptor, module, allocation, expected):
    print("\n=== TEST 3: INITIAL REP MOVSQ ===")

    copy = decryptor._observe_bulk_copy(allocation)

    expected_source = module.base + expected["source_rva"]

    check_equal(copy.source_va, expected_source, "Ciphertext source VA")
    check_equal(copy.destination_va, allocation.base, "Temporary buffer VA")
    check_equal(copy.size, allocation.size, "Ciphertext copy size")

    instruction = debugger.disassemble_one(copy.instruction_va)

    check(
        instruction.raw_bytes.startswith(b"\xF3\x48\xA5")
        or instruction.raw_bytes.startswith(b"\x48\xF3\xA5"),
        "Initial copy instruction is REP MOVSQ"
    )

    expected_next_va = copy.instruction_va + instruction.size

    check_equal(debugger.get_register("rip"), expected_next_va, "RIP after initial REP MOVSQ")

    registers = debugger.get_registers("rcx", "rsi", "rdi")

    check_equal(registers["rcx"], 0, "REP MOVSQ counter exhausted")
    check_equal(registers["rsi"], copy.source_va + copy.size, "RSI advanced past ciphertext")
    check_equal(registers["rdi"], copy.destination_va + copy.size, "RDI advanced past temporary buffer")

    print(f"[INFO] Copy instruction: 0x{copy.instruction_va:X}")
    print(f"[INFO] Next instruction: 0x{expected_next_va:X}")

    return copy


# ----------------------------------------------------------
# Test 4: CFG-based successful-decryption breakpoint discovery
# ----------------------------------------------------------

def test_decryption_success_discovery(debugger, decryptor, module, allocation, copy, expected):
    print("\n=== TEST 4: CFG-BASED SUCCESSFUL-DECRYPTION BREAKPOINT DISCOVERY ===")

    rip_before = debugger.get_register("rip")

    print(f"[INFO] RIP before CFG analysis: 0x{rip_before:X}")
    print(f"[INFO] Initial REP MOVSQ: 0x{copy.instruction_va:X}")
    print(f"[INFO] Ciphertext source: 0x{copy.source_va:X}")
    print(f"[INFO] Temporary allocation: 0x{allocation.base:X}")

    decryption_success_va = decryptor._discover_decryption_success_breakpoint(
        allocation=allocation,
        copy=copy
    )

    print(f"[INFO] Discovered successful-decryption breakpoint VA: 0x{decryption_success_va:X}")

    check(isinstance(decryption_success_va, int), "CFG discovery returned an integer address")

    check(
        module.base <= decryption_success_va < module.end,
        "Successful-decryption breakpoint is within encrypted image"
    )

    expected_decryption_success_rva = expected["expected_decryption_success_rva"]

    if expected_decryption_success_rva is not None:
        expected_decryption_success_va = module.base + expected_decryption_success_rva

        check_equal(
            decryption_success_va,
            expected_decryption_success_va,
            "Discovered successful-decryption breakpoint"
        )

    rip_after = debugger.get_register("rip")

    check_equal(rip_after, rip_before, "CFG discovery did not advance execution")

    print("\n[PASS] CFG-based successful-decryption breakpoint discovery completed.")

    return decryption_success_va


# ----------------------------------------------------------
# Test 5: Successful-decryption breakpoint
# ----------------------------------------------------------

def test_decryption_success_breakpoint(debugger, decryptor, decryption_success_va):
    print("\n=== TEST 5: SUCCESSFUL-DECRYPTION BREAKPOINT ===")

    decryptor._clear_all_breakpoints()
    debugger.set_breakpoint(decryption_success_va)

    print(f"[INFO] Waiting for successful-decryption breakpoint: 0x{decryption_success_va:X}")

    debugger.continue_execution()

    decryptor._require_rip(decryption_success_va)

    check_equal(
        debugger.get_register("rip"),
        decryption_success_va,
        "Debugger stopped at successful-decryption breakpoint"
    )

    print("[PASS] Successful-decryption breakpoint reached.")


# ----------------------------------------------------------
# Test 6: Recovered PE validation
# ----------------------------------------------------------

def test_recovered_pe(decryptor, module, copy, expected):
    print("\n=== TEST 6: RECOVERED PE VALIDATION ===")

    recovered = decryptor._parse_recovered_pe(
        source_va=copy.source_va,
        source_size=copy.size
    )

    check(recovered is not None, "Recovered PE identified")
    check_equal(recovered.oep_rva, expected["expected_oep_rva"], "Recovered OEP RVA")
    check(recovered.image_size > 0, "Recovered SizeOfImage is valid")
    check(len(recovered.sections) > 0, "Recovered PE has sections")

    calculated_oep_va = module.base + recovered.oep_rva

    print(f"[INFO] Recovered PE VA: 0x{recovered.buffer_va:X}")
    print(f"[INFO] Recovered OEP RVA: 0x{recovered.oep_rva:X}")
    print(f"[INFO] Calculated runtime OEP: 0x{calculated_oep_va:X}")
    print(f"[INFO] SizeOfImage: 0x{recovered.image_size:X}")
    print(f"[INFO] Sections: {len(recovered.sections)}")

    print("\n[PASS] Recovered PE validation completed.")

    return recovered


# ----------------------------------------------------------
# Full workflow regression test
# ----------------------------------------------------------

def test_full_workflow(debugger, decryptor, executable, expected):
    print("\n=== FULL HYPERION RECOVERY WORKFLOW ===")

    result = decryptor.run(executable)

    check_equal(result.encrypted_entry_rva, expected["encrypted_entry_rva"], "Encrypted entry RVA")
    check_equal(result.allocation.size, expected["allocation_size"], "VirtualAlloc allocation size")
    check_equal(result.oep_rva, expected["expected_oep_rva"], "Recovered OEP RVA")

    decryptor._require_rip(result.oep_va)

    check_equal(
        debugger.get_register("rip"),
        result.oep_va,
        "Debugger stopped at recovered OEP"
    )

    print("\n[PASS] Full Hyperion recovery workflow completed.")
    print("[PASS] Debugger reached the OEP stopping boundary.")


# ----------------------------------------------------------
# Sample runner
# ----------------------------------------------------------

def run_sample(name: str, expected: dict, mode: str) -> bool:
    executable = expected["path"]

    print("\n" + "=" * 72)
    print(f"TESTING: {name}")
    print(f"SAMPLE: {executable}")
    print(f"MODE: {mode}")
    print("=" * 72)

    debugger = None

    try:
        if not executable.is_file():
            raise FileNotFoundError(f"Sample not found: {executable}")

        debugger = CdbDebugger(cdb_path=CDB_PATH, command_timeout=120.0)
        decryptor = RuntimeDecryptor(debugger=debugger)

        if mode == "full":
            test_full_workflow(debugger, decryptor, executable, expected)

        else:
            module = test_encrypted_entry(debugger, decryptor, executable, expected)
            allocation = test_bootstrap(decryptor, module, expected)
            copy = test_initial_copy(debugger, decryptor, module, allocation, expected)

            decryption_success_va = test_decryption_success_discovery(
                debugger, decryptor, module, allocation, copy, expected
            )

            if mode == "decryption-success":
                test_decryption_success_breakpoint(debugger, decryptor, decryption_success_va)
                test_recovered_pe(decryptor, module, copy, expected)

        print(f"\n[PASS] {name}: {mode}")
        return True

    except Exception as exc:
        print(f"\n[FAIL] {name}: {type(exc).__name__}: {exc}")
        traceback.print_exc()
        return False

    finally:
        if debugger is not None:
            debugger.close()


# ----------------------------------------------------------
# Main
# ----------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--sample",
        choices=["bind_shell", "ransomware", "both"],
        default="bind_shell"
    )

    parser.add_argument(
        "--mode",
        choices=["discovery", "decryption-success", "full"],
        default="discovery"
    )

    args = parser.parse_args()

    if not CDB_PATH.is_file():
        print(f"[FAIL] CDB not found: {CDB_PATH}")
        return 1

    selected = list(SAMPLES) if args.sample == "both" else [args.sample]
    results = {}

    for name in selected:
        results[name] = run_sample(name, SAMPLES[name], args.mode)

    passed = sum(results.values())
    failed = len(results) - passed

    print("\n" + "=" * 72)
    print("HYPERION CFG INTEGRATION TEST SUMMARY")
    print("=" * 72)

    print(f"Passed: {passed}")
    print(f"Failed: {failed}")

    for name, success in results.items():
        print(f"  {name}: {'PASS' if success else 'FAIL'}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())