from __future__ import annotations

import argparse
from pathlib import Path

import pefile

from runners.debugger import CdbDebugger
from workflows.payload_recovery.runtime_decrypt import RuntimeDecryptor

'''
End-to-end Hyperion runtime decryption and post-OEP recovery test.

Tests:
    1. Launch encrypted executable under CDB.
    2. Monitor Hyperion bootstrap and VirtualAlloc.
    3. Identify initial REP MOVSQ.
    4. Discover successful-decryption breakpoint through CFG.
    5. Validate recovered PE.
    6. Monitor final reconstruction and reach recovered OEP.
    7. Discover and select IAT.
    8. Identify invalid thunks and resolve valid imports.
    9. Dump recovered image.
   10. Optionally reconstruct PE and validate output.

The debugger must remain paused at the OEP.


Usage:
    python test_hyperion_post_oep.py --sample bind_shell --mode dump
    python test_hyperion_post_oep.py --sample bind_shell --mode full
    python test_hyperion_post_oep.py --sample ransomware --mode dump
    python test_hyperion_post_oep.py --sample both --mode full
'''


# ----------------------------------------------------------
# Configuration
# ----------------------------------------------------------

CDB_PATH = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")

SAMPLES = {
    "bind_shell": {
        "path": Path(r"C:\analysis\bind_shell_enc.exe"),
        "encrypted_entry_rva": 0x4EB50,
        "allocation_size": 0x22010,
        "oep_rva": 0x17E0,
    },
    "ransomware": {
        "path": Path(r"C:\analysis\ransomware_enc.exe"),
        "encrypted_entry_rva": 0x5FB50,
        "allocation_size": 0x2A210,
        "oep_rva": 0x3998,
    },
}


# ----------------------------------------------------------
# Assertions
# ----------------------------------------------------------

def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)

    print(f"[PASS] {message}")


def check_equal(
    actual,
    expected,
    message: str,
    hex_value: bool = False,
) -> None:
    if hex_value:
        actual_display = f"0x{actual:X}"
        expected_display = f"0x{expected:X}"
    else:
        actual_display = repr(actual)
        expected_display = repr(expected)

    if actual != expected:
        raise AssertionError(f"{message}: expected {expected_display}, got {actual_display}")

    print(f"[PASS] {message}: {actual_display}")


# ----------------------------------------------------------
# Test 1: Hyperion recovery
# ----------------------------------------------------------

def test_hyperion_recovery(result, expected: dict) -> None:
    print("\n=== TEST 1: HYPERION RUNTIME RECOVERY ===")

    check_equal(
        result.encrypted_entry_rva,
        expected["encrypted_entry_rva"],
        "Encrypted entry RVA",
        hex_value=True,
    )
    check_equal(
        result.allocation.size,
        expected["allocation_size"],
        "Hyperion allocation size",
        hex_value=True,
    )
    check_equal(
        result.oep_rva,
        expected["oep_rva"],
        "Recovered OEP RVA",
        hex_value=True,
    )
    check_equal(
        result.oep_va,
        result.recovered_image_base + result.oep_rva,
        "Recovered OEP VA",
        hex_value=True,
    )

    check(result.recovered_image_size > 0, "Recovered image size is valid")
    check(len(result.sections) > 0, "Recovered PE sections identified")
    check(len(result.bootstrap_events) > 0, "Hyperion bootstrap events recorded")
    check(result.copy.size > 0, "Initial REP MOVSQ identified")
    check(result.intermediate_pe_va > 0, "Intermediate recovered PE identified")


# ----------------------------------------------------------
# Test 2: OEP synchronization
# ----------------------------------------------------------

def test_oep_synchronization(debugger, result) -> None:
    print("\n=== TEST 2: OEP SYNCHRONIZATION ===")

    rip = debugger.get_register("rip")
    check_equal(
        rip,
        result.oep_va,
        "CDB remains paused at recovered OEP",
        hex_value=True,
    )
    check(
        result.recovered_image_base <= rip < result.recovered_image_base + result.recovered_image_size,
        "OEP lies within recovered image",
    )


# ----------------------------------------------------------
# Test 3: IAT discovery
# ----------------------------------------------------------

def test_iat_discovery(result) -> None:
    print("\n=== TEST 3: IAT DISCOVERY ===")

    check(result.iat_start_va > 0, "IAT start VA identified")
    check(result.iat_size > 0, "IAT size identified")
    check_equal(
        result.iat_rva,
        result.iat_start_va - result.recovered_image_base,
        "IAT RVA calculation",
        hex_value=True,
    )
    check(result.iat_valid_thunks > 0, "Valid external thunks identified")
    check(result.iat_invalid_thunks >= 0, "Invalid thunk count recorded")
    check(len(result.iat_thunks) > 0, "Complete selected IAT retained")

    print(f"[INFO] IAT start: 0x{result.iat_start_va:X}")
    print(f"[INFO] IAT size: 0x{result.iat_size:X}")
    print(f"[INFO] Valid thunks: {result.iat_valid_thunks}")
    print(f"[INFO] Invalid thunks: {result.iat_invalid_thunks}")


# ----------------------------------------------------------
# Test 4: Standard / Advanced IAT candidates
# ----------------------------------------------------------

def test_iat_candidates(result) -> None:
    print("\n=== TEST 4: IAT CANDIDATE SELECTION ===")

    analysis = result.iat_analysis
    check(len(analysis.candidates) > 0, "IAT candidates discovered")
    check(analysis.selected in analysis.candidates, "Selected IAT belongs to analyzed candidates")
    print(f"[INFO] Selected candidate: {analysis.selected.name}")

    for candidate in analysis.candidates:
        print(f"[INFO] {candidate.name}: start=0x{candidate.start_va:X}, size=0x{candidate.size:X}, valid={candidate.valid_external}, invalid={candidate.invalid_total}")

    check_equal(
        result.iat_start_va,
        analysis.selected.start_va,
        "Selected IAT start matches result",
        hex_value=True,
    )
    check_equal(
        result.iat_size,
        analysis.selected.size,
        "Selected IAT size matches result",
        hex_value=True,
    )


# ----------------------------------------------------------
# Test 5: Import resolution
# ----------------------------------------------------------

def test_import_resolution(result) -> None:
    print("\n=== TEST 5: IMPORT RESOLUTION ===")

    check(len(result.loaded_modules) > 0, "Loaded modules enumerated")
    check(len(result.resolved_imports) > 0, "Imports resolved")

    for entry in result.resolved_imports:
        check(bool(entry.module_name), f"Import at 0x{entry.slot_va:X} has a module")
        check(
            entry.function_name is not None or entry.ordinal is not None,
            f"Import at 0x{entry.slot_va:X} has a name or ordinal",
        )

    print(f"[INFO] Resolved imports: {len(result.resolved_imports)}")


# ----------------------------------------------------------
# Test 6: Memory dump
# ----------------------------------------------------------

def test_memory_dump(result) -> None:
    print("\n=== TEST 6: MEMORY DUMP ===")

    dump_path = Path(result.dump_path)
    check(dump_path.exists(), "Memory dump exists")
    check_equal(
        dump_path.stat().st_size,
        result.recovered_image_size,
        "Memory dump size matches SizeOfImage",
        hex_value=True,
    )

    with dump_path.open("rb") as file:
        signature = file.read(2)

    check_equal(signature, b"MZ", "Memory dump begins with MZ")
    print(f"[INFO] Dump path: {dump_path}")


# ----------------------------------------------------------
# Test 7: PE reconstruction
# ----------------------------------------------------------

def test_pe_reconstruction(result) -> None:
    print("\n=== TEST 7: PE RECONSTRUCTION ===")

    check(result.reconstructed_path is not None, "Reconstructed output path returned")
    reconstructed_path = Path(result.reconstructed_path)
    check(reconstructed_path.exists(), "Reconstructed PE exists")
    check(reconstructed_path.stat().st_size > 0, "Reconstructed PE is not empty")

    pe = pefile.PE(str(reconstructed_path))
    try:
        check_equal(
            pe.OPTIONAL_HEADER.Magic,
            0x20B,
            "Reconstructed executable is PE32+",
            hex_value=True,
        )
        check_equal(
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            result.oep_rva,
            "Reconstructed PE entry RVA",
            hex_value=True,
        )
        check(pe.FILE_HEADER.NumberOfSections > 0, "Reconstructed PE contains sections")

        import_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ]
        check(import_directory.VirtualAddress > 0, "Import directory RVA populated")
        check(import_directory.Size > 0, "Import directory size populated")

        pe.parse_data_directories()
        check(hasattr(pe, "DIRECTORY_ENTRY_IMPORT"), "Import descriptors parse successfully")
        check(len(pe.DIRECTORY_ENTRY_IMPORT) > 0, "Reconstructed PE contains imported modules")
        print(f"[INFO] Imported modules: {len(pe.DIRECTORY_ENTRY_IMPORT)}")

        for module in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"[INFO] DLL: {module.dll.decode(errors='replace')}")
    finally:
        pe.close()

    print(f"[INFO] Reconstructed PE: {reconstructed_path}")


# ----------------------------------------------------------
# Test runner
# ----------------------------------------------------------

def run_test(sample_name: str, mode: str) -> None:
    expected = SAMPLES[sample_name]
    executable = expected["path"]

    print("\n" + "=" * 70)
    print(f"SAMPLE: {sample_name}")
    print(f"MODE: {mode}")
    print("=" * 70)

    check(executable.exists(), f"Sample exists: {executable}")
    check(CDB_PATH.exists(), f"CDB exists: {CDB_PATH}")

    debugger = CdbDebugger(cdb_path=CDB_PATH, command_timeout=120.0)
    try:
        decryptor = RuntimeDecryptor(debugger=debugger)

        # Integrated RuntimeDecryptor.run() performs Hyperion recovery,
        # OEP synchronization, IAT discovery, import resolution,
        # memory dumping, and PE reconstruction.
        result = decryptor.run(executable)

        test_hyperion_recovery(result, expected)
        test_oep_synchronization(debugger, result)
        test_iat_discovery(result)
        test_iat_candidates(result)
        test_import_resolution(result)
        test_memory_dump(result)

        if mode == "full":
            test_pe_reconstruction(result)

        # Confirm post-OEP processing did not resume execution.
        test_oep_synchronization(debugger, result)

        print("\n" + "=" * 70)
        print(f"[PASS] {sample_name}: {mode}")
        print("=" * 70)
    finally:
        debugger.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", choices=("bind_shell", "ransomware", "both"), default="bind_shell")
    parser.add_argument("--mode", choices=("dump", "full", "both"), default="dump")
    args = parser.parse_args()

    samples = ("bind_shell", "ransomware") if args.sample == "both" else (args.sample,)
    modes = ("dump", "full") if args.mode == "both" else (args.mode,)
    failures = []

    for sample_name in samples:
        for mode in modes:
            try:
                run_test(sample_name, mode)
            except Exception as exc:
                failures.append((sample_name, mode, exc))
                print(f"\n[FAIL] {sample_name}: {mode}")
                print(f"[ERROR] {type(exc).__name__}: {exc}")

    print("\n=== FINAL RESULTS ===")
    if failures:
        for sample_name, mode, error in failures:
            print(f"[FAIL] {sample_name} ({mode}): {error}")
        raise SystemExit(1)

    print("[PASS] All requested tests completed successfully.")


if __name__ == "__main__":
    main()
