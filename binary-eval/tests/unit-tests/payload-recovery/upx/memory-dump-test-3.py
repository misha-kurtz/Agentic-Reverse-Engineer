'''
Updated Memory Dump/PE reconstruction test should test three things independently:

1. every VALID_EXTERNAL thunk maps to the expected loaded module,
2. target_rva is computed correctly,
3. export lookup actually returns a function name or ordinal for as many thunks as possible.

runtime unpack
    ↓
recover OEP
    ↓
recover IAT bounds
    ↓
classify thunks
    ↓
map thunk target → loaded module
    ↓
map target RVA → export name/ordinal
    ↓
82/82 imports resolved

'''

from pathlib import Path

from runners.debugger import CdbDebugger
from runners.iat import ThunkStatus
from runners.import_resolver import ImportResolver
from workflows.payload_recovery.runtime_unpack import RuntimeUnpacker


CDB = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")

sample = Path(r"C:\analysis\bind_shell_packed.exe")

debugger = CdbDebugger(cdb_path=CDB)

unpacker = RuntimeUnpacker(debugger=debugger)

try:
    result = unpacker.run(sample)

    resolver = ImportResolver(
        result.loaded_modules
    )

    total_valid = 0
    resolved_by_name = 0
    unresolved_exports = 0

    print()
    print("[debug] Export resolution results:")

    for thunk in result.iat_thunks:
        if thunk.status != ThunkStatus.VALID_EXTERNAL:
            continue

        total_valid += 1

        resolved = resolver.resolve_thunk(
            thunk
        )

        if resolved.function_name is not None:
            resolved_by_name += 1

            symbol = (
                f"{resolved.module_name}!"
                f"{resolved.function_name}"
            )
        elif resolved.ordinal is not None:
            symbol = (
                f"{resolved.module_name}!"
                f"ordinal_{resolved.ordinal}"
            )
        else:
            unresolved_exports += 1
            symbol = (
                f"{resolved.module_name}!"
                f"<unresolved>"
            )

        print(
            f"slot=0x{resolved.slot_va:X} "
            f"target=0x{resolved.target_va:X} "
            f"rva=0x{resolved.target_rva:X} "
            f"{symbol}"
        )

    print()
    print("Summary:")
    print(f"Valid thunks:       {total_valid}")
    print(f"Resolved by name:   {resolved_by_name}")
    print(f"Unresolved exports: {unresolved_exports}")

finally:
    debugger.close()