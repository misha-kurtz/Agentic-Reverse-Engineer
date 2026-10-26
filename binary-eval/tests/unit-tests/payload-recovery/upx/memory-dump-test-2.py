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

    print()
    print("[debug] Resolved imports:")

    for thunk in result.iat_thunks:
        if thunk.status != ThunkStatus.VALID_EXTERNAL:
            continue

        resolved = resolver.resolve_thunk(
            thunk
        )

        print(
            f"slot=0x{resolved.slot_va:X} "
            f"target=0x{resolved.target_va:X} "
            f"module={resolved.module_name}"
        )

finally:
    debugger.close()