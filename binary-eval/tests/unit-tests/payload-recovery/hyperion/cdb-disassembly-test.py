'''
Unit test for validating disassembly of instructions at specific addresses using CDB (Console Debugger).
This script launches the executable and tests the specified addresses at CDB's initial debugger stop.
'''
from pathlib import Path
from runners.debugger import CdbDebugger, DebuggerError

CDB_PATH = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")
EXECUTABLE = Path(r"C:\analysis\bind_shell_enc.exe")

TEST_ADDRESSES = [
    0x14004EA4F,
    0x14004EA72,
    0x14004EA75,
    0x14004EAE6,
    0x14004F020,
    0x14004F028,
]

def test_address(debugger: CdbDebugger, address: int) -> bool:
    print(f"\n{'=' * 70}")
    print(f"TEST ADDRESS: 0x{address:X}")
    print("=" * 70)

    try:
        raw = debugger.read_instruction_bytes(address, 15)
        print(f"[PASS] Raw memory: {raw.hex(' ')}")
    except (DebuggerError, ValueError) as exc:
        print(f"[FAIL] Raw memory read: {exc}")
        return False

    print("\n[CDB DISASSEMBLY]")
    print(debugger.command(f"u 0x{address:X} L1").strip())

    try:
        instruction = debugger.disassemble_one(address)
        print(f"\n[PASS] Parsed instruction:")
        print(f"  Address:  0x{instruction.address:X}")
        print(f"  Bytes:    {instruction.raw_bytes.hex(' ')}")
        print(f"  Size:     {instruction.size}")
        print(f"  Mnemonic: {instruction.mnemonic}")
        print(f"  Operands: {instruction.operands}")

        if raw[:instruction.size] != instruction.raw_bytes:
            print("[FAIL] Parsed bytes differ from raw memory")
            return False

        print("[PASS] Instruction bytes match memory")
        return True

    except DebuggerError as exc:
        print(f"\n[FAIL] Disassembly validation: {exc}")
        return False

def main() -> None:
    print("=" * 70)
    print("CDB DISASSEMBLY VALIDATION TEST")
    print("=" * 70)

    passed = 0
    failed = 0

    with CdbDebugger(CDB_PATH) as debugger:
        debugger.launch(EXECUTABLE)
        print("[PASS] CDB launched")

        module = debugger.get_module(EXECUTABLE.name)
        print(f"[module] {module.name}: 0x{module.base:X}-0x{module.end:X}")

        for address in TEST_ADDRESSES:
            if test_address(debugger, address):
                passed += 1
            else:
                failed += 1

    print(f"\n{'=' * 70}")
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total:  {passed + failed}")

if __name__ == "__main__":
    main()