from pathlib import Path

from runners.debugger import CdbDebugger
from workflows.payload_recovery.runtime_unpack import RuntimeUnpacker


CDB = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")

sample = Path(r"C:\analysis\bind_shell_packed.exe")

debugger = CdbDebugger(cdb_path=CDB)

unpacker = RuntimeUnpacker(debugger=debugger)

try:
    result = unpacker.run(sample)

    print()
    print(f"PID:              {result.pid}")
    print(f"Image base:       0x{result.image_base:X}")
    print(f"OEP VA:           0x{result.oep_va:X}")
    print(f"OEP RVA:          0x{result.oep_rva:X}")

    print()
    print(f"IAT VA:           0x{result.iat_start_va:X}")
    print(f"IAT RVA:          0x{result.iat_rva:X}")
    print(f"IAT size:         0x{result.iat_size:X}")
    print(f"Valid thunks:     {result.iat_valid_thunks}")
    print(f"Invalid thunks:   {result.iat_invalid_thunks}")

    print()
    print(f"Memory dump:      {result.dump_path}")
    print(f"Dump exists:      {result.dump_path.exists()}")
    print(f"Dump size:        0x{result.dump_path.stat().st_size:X}")

finally:
    debugger.close()