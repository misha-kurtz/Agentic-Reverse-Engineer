'''
Test the deterministic Hyperion runtime decryption workflow.

Tests:
    1. Launch the encrypted executable under CDB.
    2. Monitor Hyperion's API bootstrap phase.
    3. Identify the candidate VirtualAlloc allocation.
    4. Locate and complete REP MOVSQ.
    5. Detect the recovered PE.
    6. Monitor VirtualProtect activity.
    7. Confirm execution reaches the recovered OEP.
    8. Compare the recovered OEP against known sample values.

Run:
    python hyperion-runtime-decrypt.py
'''

from pathlib import Path
from dataclasses import fields

from runners.debugger import CdbDebugger
from runners.dynamic_cfg import ControlFlowAnalyzer, collect_cfg_instructions
from workflows.payload_recovery.runtime_decrypt import (RuntimeDecryptor,RuntimeDecryptError)


# --------------------------------------------------------------
# Configuration
# --------------------------------------------------------------

CDB_PATH = Path(
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
)

SAMPLES = {
    "ransomware": {
        "path": Path(r"C:\analysis\hyperion_ransomware.exe"),
        "expected_encrypted_ep_rva": 0x5FB50,
        "expected_allocation_size": 0x2A210,
        "expected_oep_rva": 0x3998,
    },
    "bind_shell": {
        "path": Path(r"C:\analysis\hyperion_bind_shell.exe"),
        "expected_encrypted_ep_rva": 0x4EB50,
        "expected_allocation_size": 0x22010,
        "expected_oep_rva": 0x17E0,
    },
}

# Select one sample for the initial test.
SAMPLE_NAME = "ransomware"


# --------------------------------------------------------------
# Helpers
# --------------------------------------------------------------

def print_section(title: str) -> None:
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def print_result(result) -> None:
    '''
    Display the recovered information.
    '''

    print_section("HYPERION RECOVERY RESULTS")

    print(f"Input:               {result.input_path}")
    print(f"Process ID:          {result.pid}")

    print(
        f"Encrypted image:     "
        f"0x{result.encrypted_image_base:X}"
    )

    print(
        f"Encrypted EP RVA:    "
        f"0x{result.encrypted_entry_rva:X}"
    )

    print()
    print("Allocation")

    print(f"  Base:              0x{result.allocation.base:X}")
    print(f"  Size:              0x{result.allocation.size:X}")

    print(
        f"  Allocation flags:  "
        f"0x{result.allocation.allocation_type:X}"
    )

    print(
        f"  Protection:        "
        f"0x{result.allocation.protection:X}"
    )

    print()
    print("Bulk Copy")

    print(
        f"  Instruction:       "
        f"0x{result.copy.instruction_va:X}"
    )

    print(
        f"  Source:            "
        f"0x{result.copy.source_va:X}"
    )

    print(
        f"  Destination:       "
        f"0x{result.copy.destination_va:X}"
    )

    print(f"  Size:              0x{result.copy.size:X}")

    print()
    print("Recovered PE")

    print(
        f"  Intermediate PE:   "
        f"0x{result.intermediate_pe_va:X}"
    )

    print(
        f"  Recovered image:   "
        f"0x{result.recovered_image_base:X}"
    )

    print(
        f"  Image size:        "
        f"0x{result.recovered_image_size:X}"
    )

    print(f"  OEP RVA:           0x{result.oep_rva:X}")
    print(f"  OEP VA:            0x{result.oep_va:X}")

    print()
    print("Recovered Sections")

    for section in result.sections:
        print(
            f"  {section.name:<10} "
            f"RVA=0x{section.rva:08X} "
            f"VSIZE=0x{section.virtual_size:08X} "
            f"EXEC={section.executable}"
        )

    print()
    print("VirtualProtect Events")

    for index, event in enumerate(
        result.protection_events,
        start=1,
    ):
        print(
            f"  [{index}] "
            f"Address=0x{event.address:X} "
            f"Size=0x{event.size:X} "
            f"Protection=0x{event.new_protection:X} "
            f"Success={event.succeeded}"
        )


def validate_result(result, sample: dict) -> bool:
    '''
    Compare the recovery results with known sample values.
    '''

    print_section("VALIDATION")

    checks = {
        "Encrypted entry RVA": (
            result.encrypted_entry_rva
            == sample["expected_encrypted_ep_rva"]
        ),
        "Allocation size": (
            result.allocation.size
            == sample["expected_allocation_size"]
        ),
        "Bulk copy size": (
            result.copy.size
            == result.allocation.size
        ),
        "Bulk copy destination": (
            result.copy.destination_va
            == result.allocation.base
        ),
        "Recovered OEP RVA": (
            result.oep_rva
            == sample["expected_oep_rva"]
        ),
        "OEP VA calculation": (
            result.oep_va
            == result.recovered_image_base + result.oep_rva
        ),
        "Recovered PE within source region": (
            result.copy.source_va
            <= result.intermediate_pe_va
            < result.copy.source_va + result.copy.size
        ),
    }

    for name, passed in checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {name}")

    return all(checks.values())

def compare_cfg_with_manual(debugger, scan_start, scan_end, manual_addresses=None):
    print_section("TARGET CFG COMPARISON")

    analyzer = ControlFlowAnalyzer(debugger, max_instructions=1000)
    graph = analyzer.analyze(scan_start, scan_start, scan_end)
    result = collect_cfg_instructions(graph)

    decoded = {instruction.address for instruction in result.instructions}
    manual = set(manual_addresses or [])

    print(f"Entry:                0x{graph.entry_va:X}")
    print(f"Analysis start:       0x{scan_start:X}")
    print(f"Analysis end:         0x{scan_end:X}")
    print(f"Decoded instructions: {len(decoded)}")
    print(f"Unresolved:           {len(result.unresolved)}")
    print(f"Decode errors:        {len(result.decode_errors)}")
    print(f"Pending:              {len(result.pending)}")
    print(f"Truncated:            {result.truncated}")

    print("\nDecoded instructions:")

    for instruction in result.instructions:
        print(f"0x{instruction.address:X}: {instruction.text}")

    if manual:
        print("\nManual comparison:")
        print(f"Matching addresses: {len(decoded & manual)}")
        print(f"Missing addresses:  {len(manual - decoded)}")

        for address in sorted(manual - decoded):
            print(f"[MISSING] 0x{address:X}")

    if result.decode_errors:
        print("\nDecode errors:")

        for address, error in sorted(result.decode_errors.items()):
            print(f"0x{address:X}: {error}")

    return graph


# --------------------------------------------------------------
# Main
# --------------------------------------------------------------

def main() -> None:
    sample = SAMPLES[SAMPLE_NAME]
    executable = sample["path"]

    print_section("HYPERION RUNTIME DECRYPTION TEST")

    print(f"Sample: {SAMPLE_NAME}")
    print(f"Executable: {executable}")
    print(f"CDB: {CDB_PATH}")

    if not CDB_PATH.is_file():
        raise FileNotFoundError(
            f"CDB executable not found: {CDB_PATH}"
        )

    if not executable.is_file():
        raise FileNotFoundError(
            f"Sample not found: {executable}"
        )

    debugger = CdbDebugger(
        cdb_path=CDB_PATH
    )

    decryptor = RuntimeDecryptor(
        debugger=debugger,
        max_bootstrap_events=256,
        max_copy_instructions=512,
        max_monitor_events=2048,
        max_header_offset=0x40,
    )

    try:
        result = decryptor.run(executable)

        print_result(result)

        passed = validate_result(result, sample)

        print_section("FINAL STATUS")

        if passed:
            print("[PASS] Hyperion runtime recovery completed")
        else:
            print("[FAIL] Recovery completed with mismatched values")

    except RuntimeDecryptError as exc:
        print_section("RECOVERY ERROR")
        print(f"[ERROR] {exc}")
        raise

    finally:
        debugger.close()


if __name__ == "__main__":
    main()