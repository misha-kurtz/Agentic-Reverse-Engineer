'''
Updated Memory Dump/Import Rebuilder/PE reconstruction test.

Tests:

1. Every VALID_EXTERNAL thunk maps to a loaded module.
2. target_rva is computed correctly.
3. Export lookup resolves function name or ordinal.
4. Resolved imports are grouped correctly by DLL.
5. Layout calculcation.
6. Binary serialization.
7. Serialized import section parser-style verification.

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

sample = Path(r"C:\analysis\ransomware_packed.exe")

debugger = CdbDebugger(cdb_path=CDB)

unpacker = RuntimeUnpacker(debugger=debugger)

def read_c_string(
    data: bytes,
    offset: int,
) -> str:

    end = data.find(
        b"\x00",
        offset,
    )

    if end == -1:
        raise RuntimeError(
            f"Unterminated string at offset 0x{offset:X}"
        )

    return data[offset:end].decode("ascii")


def verify_import_section(
    section_data: bytes,
    layout,
    pointer_size: int = 8,
) -> None:

    if pointer_size == 8:
        thunk_format = "<Q"
        ordinal_flag = 0x8000000000000000
    elif pointer_size == 4:
        thunk_format = "<I"
        ordinal_flag = 0x80000000
    else:
        raise ValueError(
            "pointer_size must be 4 or 8"
        )

    def rva_to_offset(
        rva: int,
    ) -> int:

        offset = rva - layout.section_rva

        if offset < 0 or offset >= len(section_data):
            raise RuntimeError(
                f"RVA 0x{rva:X} falls outside serialized section"
            )

        return offset

    print()
    print("[debug] Parser-style verification:")

    for module_layout in layout.modules:
        module = module_layout.module

        #
        # Parse IMAGE_IMPORT_DESCRIPTOR.
        #
        descriptor_offset = rva_to_offset(
            module_layout.descriptor_rva
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

        if original_first_thunk != module_layout.int_rva:
            raise RuntimeError(
                f"{module.name}: incorrect OriginalFirstThunk"
            )

        if name_rva != module_layout.dll_name_rva:
            raise RuntimeError(
                f"{module.name}: incorrect Name RVA"
            )

        if first_thunk != module_layout.iat_rva:
            raise RuntimeError(
                f"{module.name}: incorrect FirstThunk"
            )

        if time_date_stamp != 0:
            raise RuntimeError(
                f"{module.name}: TimeDateStamp is not zero"
            )

        if forwarder_chain != 0:
            raise RuntimeError(
                f"{module.name}: ForwarderChain is not zero"
            )

        #
        # Parse DLL name.
        #
        dll_name_offset = rva_to_offset(
            name_rva
        )

        parsed_dll_name = read_c_string(
            section_data,
            dll_name_offset,
        )

        if parsed_dll_name != module.name:
            raise RuntimeError(
                f"DLL name mismatch: "
                f"expected {module.name}, "
                f"got {parsed_dll_name}"
            )

        #
        # Parse INT and IAT entries.
        #
        int_offset = rva_to_offset(
            original_first_thunk
        )

        iat_offset = rva_to_offset(
            first_thunk
        )

        for index, resolved in enumerate(
            module.imports
        ):
            int_value = struct.unpack_from(
                thunk_format,
                section_data,
                int_offset + (index * pointer_size),
            )[0]

            iat_value = struct.unpack_from(
                thunk_format,
                section_data,
                iat_offset + (index * pointer_size),
            )[0]

            if int_value != iat_value:
                raise RuntimeError(
                    f"{module.name} import {index}: "
                    "INT and IAT values differ"
                )

            expected_name_rva = (
                module_layout.import_name_rvas[index]
            )

            #
            # Import by name.
            #
            if expected_name_rva is not None:
                if int_value != expected_name_rva:
                    raise RuntimeError(
                        f"{module.name} import {index}: "
                        "incorrect import-name RVA"
                    )

                name_offset = rva_to_offset(
                    int_value
                )

                hint = struct.unpack_from(
                    "<H",
                    section_data,
                    name_offset,
                )[0]

                parsed_function_name = read_c_string(
                    section_data,
                    name_offset + 2,
                )

                if hint != 0:
                    raise RuntimeError(
                        f"{module.name}!{resolved.function_name}: "
                        "expected hint 0"
                    )

                if parsed_function_name != resolved.function_name:
                    raise RuntimeError(
                        f"Function name mismatch: "
                        f"expected {resolved.function_name}, "
                        f"got {parsed_function_name}"
                    )

            #
            # Import by ordinal.
            #
            elif resolved.ordinal is not None:
                expected_value = (
                    ordinal_flag
                    | resolved.ordinal
                )

                if int_value != expected_value:
                    raise RuntimeError(
                        f"{module.name} ordinal "
                        f"{resolved.ordinal}: "
                        "incorrect thunk value"
                    )

            else:
                raise RuntimeError(
                    f"{module.name} import {index} "
                    "has neither name nor ordinal"
                )

        #
        # Verify INT terminator.
        #
        int_terminator = struct.unpack_from(
            thunk_format,
            section_data,
            int_offset + (
                len(module.imports)
                * pointer_size
            ),
        )[0]

        if int_terminator != 0:
            raise RuntimeError(
                f"{module.name}: INT is not null terminated"
            )

        #
        # Verify IAT terminator.
        #
        iat_terminator = struct.unpack_from(
            thunk_format,
            section_data,
            iat_offset + (
                len(module.imports)
                * pointer_size
            ),
        )[0]

        if iat_terminator != 0:
            raise RuntimeError(
                f"{module.name}: IAT is not null terminated"
            )

        print(
            f"[debug] {module.name}: "
            f"{len(module.imports)} imports verified"
        )

    #
    # Verify final null IMAGE_IMPORT_DESCRIPTOR.
    #
    null_descriptor_rva = (
        layout.descriptor_rva
        + (len(layout.modules) * 20)
    )

    null_descriptor_offset = rva_to_offset(
        null_descriptor_rva
    )

    null_descriptor = section_data[
        null_descriptor_offset:
        null_descriptor_offset + 20
    ]

    if null_descriptor != b"\x00" * 20:
        raise RuntimeError(
            "Final IMAGE_IMPORT_DESCRIPTOR is not null"
        )

    print(
        "[debug] Null descriptor verified"
    )

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

    print()
    print("[debug] Serialized import section:")
    print(f"Expected size:       0x{layout.section_size:X}")
    print(f"Actual size:         0x{len(section_data):X}")

    if len(section_data) != layout.section_size:
        raise RuntimeError(
            "Serialized import section size does not match layout"
        )

    verify_import_section(
        section_data,
        layout,
        pointer_size=8,
    )


finally:
    debugger.close()

