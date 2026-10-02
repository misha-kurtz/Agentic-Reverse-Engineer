'''
Updated Memory Dump / Import Rebuilder / PE Reconstruction integration test.

Tests:

1. Every VALID_EXTERNAL thunk maps to a loaded module.
2. target_rva is computed correctly.
3. Export lookup resolves each valid thunk by function name or ordinal.
4. Resolved imports are grouped correctly by DLL.
5. ImportModule objects are built with deterministic module/import ordering.
6. Import section layout is calculated correctly.
7. Import descriptors, DLL names, IMAGE_IMPORT_BY_NAME records, INTs, and IATs are serialized correctly.
8. Serialized import section passes parser-style verification.
9. PE reconstruction appends a new .scy import section.
10. NumberOfSections and SizeOfImage are updated correctly.
11. IMAGE_DIRECTORY_ENTRY_IMPORT points into the new .scy section.
12. pefile can parse the reconstructed import directory.
13. Parsed reconstructed import count matches the resolved import count.
14. Reconstructed PE preserves the recovered OEP.

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
build ImportModule objects
↓
calculate import section layout
↓
serialize import descriptors / names / INT / IAT
↓
verify serialized import section
↓
PEReconstructor(...)
↓
reconstruct(..., import_modules)
↓
append .scy section
↓
update section table / NumberOfSections / SizeOfImage
↓
update IMAGE_DIRECTORY_ENTRY_IMPORT
↓
write reconstructed PE
↓
open reconstructed PE with pefile
↓
find .scy
↓
verify Import Directory → .scy
↓
parse DIRECTORY_ENTRY_IMPORT
↓
compare parsed import count
↓
verify recovered OEP

NOTE: .scy RVA currently hardcoded as 0x30000
'''


from pathlib import Path
import struct
import pefile

from capstone import (
    Cs,
    CS_ARCH_X86,
    CS_MODE_64,
)

from capstone.x86_const import (
    X86_OP_MEM,
    X86_REG_RIP,
)

from runners.debugger import CdbDebugger
from runners.iat import ThunkStatus
from runners.import_resolver import ImportResolver
from runners.reconstruction import PEReconstructor
from runners.import_rebuilder import (
    build_import_modules,
    build_import_section,
    calculate_layout,
    group_imports_by_module,
)
from workflows.payload_recovery.runtime_unpack import RuntimeUnpacker


CDB = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")

sample = Path(r"C:\analysis\bind_shell_packed.exe")
reconstructed_path = Path(r"C:\analysis\bind_shell_reconstructed.exe")

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

# Verify IAT reference patches.
# instruction RVA + instruction size + new disp32 == expected new .scy IAT RVA
def verify_iat_reference_patches(
    output_data: bytearray,
    pe,
    patch_result,
) -> None:

    disassembler = Cs(
        CS_ARCH_X86,
        CS_MODE_64,
    )

    disassembler.detail = True

    verified = 0

    print()
    print("[debug] Verifying patched IAT references:")

    for patch in patch_result.patches:
        containing_section = None

        for section in pe.sections:
            section_start = section.VirtualAddress

            section_end = (
                section_start
                + max(
                    section.Misc_VirtualSize,
                    section.SizeOfRawData,
                )
            )

            if (
                section_start
                <= patch.instruction_rva
                < section_end
            ):
                containing_section = section
                break

        if containing_section is None:
            raise RuntimeError(
                f"Patched instruction RVA "
                f"0x{patch.instruction_rva:X} "
                "does not belong to a PE section"
            )

        instruction_offset = (
            containing_section.PointerToRawData
            + (
                patch.instruction_rva
                - containing_section.VirtualAddress
            )
        )

        instruction_bytes = bytes(
            output_data[
                instruction_offset:
                instruction_offset + 15
            ]
        )

        instructions = list(
            disassembler.disasm(
                instruction_bytes,
                patch.instruction_rva,
                count=1,
            )
        )

        if not instructions:
            raise RuntimeError(
                f"Unable to disassemble patched instruction "
                f"at RVA 0x{patch.instruction_rva:X}"
            )

        instruction = instructions[0]

        resolved_target = None

        for operand in instruction.operands:
            if operand.type != X86_OP_MEM:
                continue

            if operand.mem.base != X86_REG_RIP:
                continue

            resolved_target = (
                instruction.address
                + instruction.size
                + operand.mem.disp
            )

            break

        if resolved_target is None:
            raise RuntimeError(
                f"Patched instruction at "
                f"RVA 0x{patch.instruction_rva:X} "
                "no longer contains a RIP-relative memory operand"
            )

        if resolved_target != patch.new_slot_rva:
            raise RuntimeError(
                f"Incorrect patched target at "
                f"RVA 0x{patch.instruction_rva:X}: "
                f"expected 0x{patch.new_slot_rva:X}, "
                f"got 0x{resolved_target:X}"
            )

        if patch.function_name is not None:
            symbol = (
                f"{patch.module_name}!"
                f"{patch.function_name}"
            )
        else:
            symbol = (
                f"{patch.module_name}!"
                f"ordinal_{patch.ordinal}"
            )

        print(
            f"RVA 0x{patch.instruction_rva:X}: "
            f"{instruction.mnemonic} "
            f"{instruction.op_str} "
            f"-> 0x{resolved_target:X} "
            f"{symbol}"
        )

        verified += 1

    if verified != patch_result.patch_count:
        raise RuntimeError(
            "Not every IAT reference patch was verified"
        )

    print()
    print("IAT Patch Verification Summary:")
    print(
        f"Patches reported:    "
        f"{patch_result.patch_count}"
    )
    print(
        f"Patches verified:    "
        f"{verified}"
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
        #
    # Test import section layout calculation.
    #
    test_pe = pefile.PE(
        data=result.dump_path.read_bytes(),
        fast_load=False,
    )

    last_section = test_pe.sections[-1]

    last_section_end = (
        last_section.VirtualAddress
        + max(
            last_section.Misc_VirtualSize,
            last_section.SizeOfRawData,
        )
    )

    section_alignment = (
        test_pe.OPTIONAL_HEADER.SectionAlignment
    )

    section_rva = (
        last_section_end
        + section_alignment
        - 1
    ) & ~(section_alignment - 1)

    test_pe.close()

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

    verify_import_section(
        section_data,
        layout,
        pointer_size=8,
    )

    #
    # Test PE reconstruction with rebuilt import section.
    #
    reconstructor = PEReconstructor(memory_dump_path=result.dump_path)

    reconstruction_result = reconstructor.reconstruct(
        output_path=reconstructed_path,
        oep_rva=result.oep_rva,
        import_modules=import_modules,
        runtime_image_base=result.image_base,
        packed_entry_rva=result.packed_entry_rva,
        stub_jump_rva=result.stub_jump_rva,
    )

    if reconstruction_result.iat_patch_result is None:
        raise RuntimeError(
            "PE reconstruction did not produce an IAT patch result"
        )

    print()
    print("[debug] PE reconstruction:")
    print(f"Output:              {reconstruction_result.output_path}")
    print(f"Output size:         0x{reconstruction_result.output_size:X}")
    print(f"OEP RVA:             0x{reconstruction_result.recovered_oep_rva:X}")

    print()
    print("[debug] Reconstructed sections:")

    for section in reconstruction_result.sections:
        print(
            f"{section.name:<8} "
            f"VA=0x{section.virtual_address:X} "
            f"VS=0x{section.virtual_size:X} "
            f"RAW=0x{section.raw_offset:X} "
            f"RS=0x{section.raw_size:X}"
        )

    #
    # Reopen/parse reconstructed PE via pefile.
    #
    rebuilt = pefile.PE(
        str(reconstructed_path),
        fast_load=False,
    )

    reconstructed_data = bytearray(reconstructed_path.read_bytes())

    verify_iat_reference_patches(
        output_data=reconstructed_data,
        pe=rebuilt,
        patch_result=(
            reconstruction_result.iat_patch_result
        ),
    )

    print()
    print("[debug] Reconstructed PE validation:")

    print(
        f"NumberOfSections:    "
        f"{rebuilt.FILE_HEADER.NumberOfSections}"
    )

    print(
        f"SizeOfImage:         "
        f"0x{rebuilt.OPTIONAL_HEADER.SizeOfImage:X}"
    )

    print(
        f"AddressOfEntryPoint: "
        f"0x{rebuilt.OPTIONAL_HEADER.AddressOfEntryPoint:X}"
    )

    scy_section = None

    for section in rebuilt.sections:
        section_name = (
            section.Name
            .rstrip(b"\x00")
            .decode(errors="replace")
        )

        if section_name == ".scy":
            scy_section = section
            break

    if scy_section is None:
        raise RuntimeError(
            "Reconstructed PE does not contain .scy section"
        )

    print()
    print("[debug] .scy section:")
    print(
        f"VirtualAddress:      "
        f"0x{scy_section.VirtualAddress:X}"
    )
    print(
        f"VirtualSize:         "
        f"0x{scy_section.Misc_VirtualSize:X}"
    )
    print(
        f"Raw offset:          "
        f"0x{scy_section.PointerToRawData:X}"
    )
    print(
        f"Raw size:            "
        f"0x{scy_section.SizeOfRawData:X}"
    )

    import_directory = (
        rebuilt.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY[
                "IMAGE_DIRECTORY_ENTRY_IMPORT"
            ]
        ]
    )

    print()
    print("[debug] Import directory:")
    print(
        f"RVA:                 "
        f"0x{import_directory.VirtualAddress:X}"
    )
    print(
        f"Size:                "
        f"0x{import_directory.Size:X}"
    )

    scy_start = scy_section.VirtualAddress
    scy_end = (
        scy_start
        + scy_section.Misc_VirtualSize
    )

    if not (
        scy_start
        <= import_directory.VirtualAddress
        < scy_end
    ):
        raise RuntimeError(
            "Import directory does not point inside .scy"
        )

    rebuilt.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY[
                "IMAGE_DIRECTORY_ENTRY_IMPORT"
            ]
        ]
    )

    if not hasattr(
        rebuilt,
        "DIRECTORY_ENTRY_IMPORT",
    ):
        raise RuntimeError(
            "pefile could not parse reconstructed imports"
        )

    print()
    print("[debug] Parsed reconstructed imports:")

    parsed_import_total = 0

    for descriptor in rebuilt.DIRECTORY_ENTRY_IMPORT:
        dll_name = descriptor.dll.decode(
            errors="replace"
        )

        print()
        print(
            f"{dll_name}: "
            f"{len(descriptor.imports)} imports"
        )

        for imported in descriptor.imports:
            parsed_import_total += 1

            if imported.name is not None:
                symbol = imported.name.decode(
                    errors="replace"
                )
            else:
                symbol = (
                    f"ordinal_{imported.ordinal}"
                )

            print(
                f"  {symbol}"
            )


finally:
    debugger.close()

