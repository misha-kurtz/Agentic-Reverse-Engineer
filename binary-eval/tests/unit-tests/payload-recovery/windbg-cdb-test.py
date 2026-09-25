from pathlib import Path

from runners.debugger import CdbDebugger
from workflows.payload_recovery.runtime_unpack import (
    RuntimeUnpacker,
)


CDB = Path(
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
)

sample = Path(
    r"C:analysis\bind_shell_packed.exe"
)

debugger = CdbDebugger(
    cdb_path=CDB,
)

unpacker = RuntimeUnpacker(
    debugger=debugger,
)

result = unpacker.run(
    sample
)

print()
print(f"PID:             {result.pid}")
print(f"Image base:      0x{result.image_base:X}")
print(f"Packed EP VA:    0x{result.packed_entry_va:X}")
print(f"Packed EP RVA:   0x{result.packed_entry_rva:X}")
print(f"Saved RBX slot:  0x{result.saved_rbx_slot:X}")
print(f"Stub JMP:        0x{result.stub_jump_va:X}")
print(f"OEP VA:          0x{result.oep_va:X}")
print(f"OEP RVA:         0x{result.oep_rva:X}")
print(
    f"Transition:      "
    f"{result.source_section} -> "
    f"{result.destination_section}"
)