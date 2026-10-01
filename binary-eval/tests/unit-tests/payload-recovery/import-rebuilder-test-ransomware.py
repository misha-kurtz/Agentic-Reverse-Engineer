'''
Updated Memory Dump/PE reconstruction test.

Tests:

1. Every VALID_EXTERNAL thunk maps to a loaded module.
2. target_rva is computed correctly.
3. Export lookup resolves function name or ordinal.
4. Resolved imports are grouped correctly by DLL.

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
group resolved imports by DLL
'''

from pathlib import Path

from runners.debugger import CdbDebugger
from runners.iat import ThunkStatus
from runners.import_resolver import ImportResolver
from runners.import_rebuilder import group_imports_by_module, build_import_modules
from workflows.payload_recovery.runtime_unpack import RuntimeUnpacker


CDB = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")

sample = Path(r"C:\analysis\ransomware_packed.exe")

debugger = CdbDebugger(cdb_path=CDB)

unpacker = RuntimeUnpacker(debugger=debugger)

try:
    result = unpacker.run(sample)

    resolver = ImportResolver(result.loaded_modules)

    total_valid = 0
    resolved_by_name = 0
    resolved_by_ordinal = 0
    unresolved_exports = 0

    resolved_imports = []

    print()
    print("[debug] Export resolution results:")

    for thunk in result.iat_thunks:
        if thunk.status != ThunkStatus.VALID_EXTERNAL:
            continue

        total_valid += 1
        resolved = resolver.resolve_thunk(thunk)
        resolved_imports.append(resolved)

        if resolved.function_name is not None:
            resolved_by_name += 1
            symbol = f"{resolved.module_name}!{resolved.function_name}"

        elif resolved.ordinal is not None:
            resolved_by_ordinal += 1
            symbol = f"{resolved.module_name}!ordinal_{resolved.ordinal}"

        else:
            unresolved_exports += 1
            symbol = f"{resolved.module_name}!<unresolved>"

        print(
            f"slot=0x{resolved.slot_va:X} "
            f"target=0x{resolved.target_va:X} "
            f"rva=0x{resolved.target_rva:X} "
            f"{symbol}"
        )

    print()
    print("Resolution Summary:")
    print(f"Valid thunks:        {total_valid}")
    print(f"Resolved by name:    {resolved_by_name}")
    print(f"Resolved by ordinal: {resolved_by_ordinal}")
    print(f"Unresolved exports:  {unresolved_exports}")

    #
    # Test import_rebuilder grouping.
    #
    grouped_imports = group_imports_by_module(resolved_imports)

    print()
    print("[debug] Grouped imports:")

    grouped_total = 0

    for module_name, imports in grouped_imports.items():
        print()
        print(f"{module_name}: {len(imports)} imports")

        for resolved in imports:
            grouped_total += 1

            if resolved.function_name is not None:
                symbol = resolved.function_name

            elif resolved.ordinal is not None:
                symbol = f"ordinal_{resolved.ordinal}"

            else:
                symbol = "<unresolved>"

            print(f"  slot=0x{resolved.slot_va:X} {symbol}")

    print()
    print("Grouping Summary:")
    print(f"Modules:             {len(grouped_imports)}")
    print(f"Grouped imports:     {grouped_total}")
    print(f"Resolved imports:    {len(resolved_imports)}")

    if grouped_total != len(resolved_imports):
        raise RuntimeError("Import grouping lost or duplicated imports")

        import_modules = build_import_modules(resolved_imports)

    print()
    print("[debug] Import modules:")

    for module in import_modules:
        print()
        print(f"{module.name}: {len(module.imports)} imports")

        for resolved in module.imports:
            if resolved.function_name is not None:
                symbol = resolved.function_name
            elif resolved.ordinal is not None:
                symbol = f"ordinal_{resolved.ordinal}"
            else:
                symbol = "<unresolved>"

            print(
                f"  slot=0x{resolved.slot_va:X} "
                f"{symbol}"
            )

finally:
    debugger.close()

