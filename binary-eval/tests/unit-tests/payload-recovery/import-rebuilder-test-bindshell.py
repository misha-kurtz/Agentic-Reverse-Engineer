'''
Updated Memory Dump/PE reconstruction test.

Tests:

1. Every VALID_EXTERNAL thunk maps to a loaded module.
2. target_rva is computed correctly.
3. Export lookup resolves function name or ordinal.
4. Resolved imports are grouped correctly by DLL.
5. Layout calculcation.
6. Binary serialization.

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
    ↓
build import modules
    ↓
calculate layout
    ↓
serialize import section
    ↓
validate null import descriptor
'''

from pathlib import Path
import struct

from runners.debugger import CdbDebugger
from runners.iat import ThunkStatus
from runners.import_resolver import ImportResolver
from runners.import_rebuilder import (
    build_import_modules,
    build_import_section,
    calculate_layout,
    group_imports_by_module,
)
from workflows.payload_recovery.runtime_unpack import RuntimeUnpacker


CDB = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")

sample = Path(r"C:\analysis\bind_shell_packed.exe")

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

    #
    # Test import section layout calculation.
    #
    section_rva = 0x30000

    layout = calculate_layout(
        import_modules,
        section_rva=section_rva,
    )

    print()
    print("[debug] Import section layout:")
    print(f"Section RVA:         0x{layout.section_rva:X}")
    print(f"Section end RVA:     0x{layout.section_end_rva:X}")
    print(f"Section size:        0x{layout.section_size:X}")
    print(f"Descriptor RVA:      0x{layout.descriptor_rva:X}")
    print(f"Descriptor size:     0x{layout.descriptor_size:X}")

    layout_import_total = 0

    for module_layout in layout.modules:
        module = module_layout.module
        layout_import_total += len(module.imports)

        print()
        print(f"{module.name}:")
        print(f"  Descriptor RVA:    0x{module_layout.descriptor_rva:X}")
        print(f"  DLL name RVA:      0x{module_layout.dll_name_rva:X}")
        print(f"  INT RVA:           0x{module_layout.int_rva:X}")
        print(f"  INT size:          0x{module_layout.int_size:X}")
        print(f"  IAT RVA:           0x{module_layout.iat_rva:X}")
        print(f"  IAT size:          0x{module_layout.iat_size:X}")
        print(f"  Imports:           {len(module.imports)}")

        if module_layout.int_rva % 8 != 0:
            raise RuntimeError(
                f"{module.name} INT is not 8-byte aligned"
            )

        if module_layout.iat_rva % 8 != 0:
            raise RuntimeError(
                f"{module.name} IAT is not 8-byte aligned"
            )

        expected_thunk_size = (len(module.imports) + 1) * 8

        if module_layout.int_size != expected_thunk_size:
            raise RuntimeError(
                f"{module.name} INT size is incorrect"
            )

        if module_layout.iat_size != expected_thunk_size:
            raise RuntimeError(
                f"{module.name} IAT size is incorrect"
            )

    print()
    print("Layout Summary:")
    print(f"Modules:             {len(layout.modules)}")
    print(f"Imports:             {layout_import_total}")
    print(f"Section size:        0x{layout.section_size:X}")

    if layout_import_total != len(resolved_imports):
        raise RuntimeError(
            "Import layout lost or duplicated imports"
        )

    #
    # Test import section serialization.
    #
    section_data = build_import_section(
        layout,
        pointer_size=8,
    )

    print()
    print("[debug] Serialized import section:")
    print(f"Expected size:       0x{layout.section_size:X}")
    print(f"Actual size:         0x{len(section_data):X}")

    if len(section_data) != layout.section_size:
        raise RuntimeError(
            "Serialized import section size does not match layout"
        )

    for module_layout in layout.modules:
        descriptor_offset = (
            module_layout.descriptor_rva
            - layout.section_rva
        )

        (
            original_first_thunk,
            time_date_stamp,
            forwarder_chain,
            name_rva,
            first_thunk,
        ) = struct.unpack_from(
            "<IIIII",
            section_data,
            descriptor_offset,
        )

        print()
        print(
            f"[debug] Descriptor: "
            f"{module_layout.module.name}"
        )
        print(
            f"  OriginalFirstThunk: "
            f"0x{original_first_thunk:X}"
        )
        print(
            f"  Name:               "
            f"0x{name_rva:X}"
        )
        print(
            f"  FirstThunk:         "
            f"0x{first_thunk:X}"
        )

        if original_first_thunk != module_layout.int_rva:
            raise RuntimeError(
                f"{module_layout.module.name} "
                "OriginalFirstThunk is incorrect"
            )

        if name_rva != module_layout.dll_name_rva:
            raise RuntimeError(
                f"{module_layout.module.name} "
                "Name RVA is incorrect"
            )

        if first_thunk != module_layout.iat_rva:
            raise RuntimeError(
                f"{module_layout.module.name} "
                "FirstThunk is incorrect"
            )

        if time_date_stamp != 0:
            raise RuntimeError(
                "TimeDateStamp should be zero"
            )

        if forwarder_chain != 0:
            raise RuntimeError(
                "ForwarderChain should be zero"
            )

    null_descriptor_rva = (
        layout.descriptor_rva
        + (len(layout.modules) * 20)
    )

    null_descriptor_offset = (
        null_descriptor_rva
        - layout.section_rva
    )

    null_descriptor = section_data[
        null_descriptor_offset:
        null_descriptor_offset + 20
    ]

    if null_descriptor != b"\x00" * 20:
        raise RuntimeError(
            "Final import descriptor is not null"
        )

    print()
    print("[debug] Null import descriptor: OK")

finally:
    debugger.close()

