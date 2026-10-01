# binary-eval/runners/import_rebuilder.py

'''
import_rebuilder.py
    list[ResolvedImport]
        ↓
    group by module
        ↓
    prepare import descriptors / thunk arrays / names
        ↓
    write rebuilt import structures into reconstructed PE

'''
from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict
import struct

from runners.import_resolver import ImportResolutionError, ResolvedImport

@dataclass(frozen=True)
class ImportModule:
    name: str
    imports: tuple[ResolvedImport, ...]

@dataclass(frozen=True)
class ImportModuleLayout:
    module: ImportModule
    descriptor_rva: int
    dll_name_rva: int
    import_name_rvas: tuple[int | None, ...]
    int_rva: int
    iat_rva: int
    int_size: int
    iat_size: int

@dataclass(frozen=True)
class ImportLayout:
    section_rva: int
    section_size: int
    descriptor_rva: int
    descriptor_size: int
    modules: tuple[ImportModuleLayout, ...]

    @property
    def section_end_rva(self) -> int:
        return self.section_rva + self.section_size

def group_imports_by_module(
    imports: list[ResolvedImport],
) -> dict[str, list[ResolvedImport]]:

    grouped: dict[
        str,
        list[ResolvedImport]
    ] = defaultdict(list)

    for resolved in imports:
        grouped[
            resolved.module_name
        ].append(
            resolved
        )

    return dict(grouped)

def normalize_module_name(
    name: str,
) -> str:

    if name.lower().endswith(
        ".dll"
    ):
        return name

    return f"{name}.dll"

def build_import_modules(
    imports: list[ResolvedImport],
) -> tuple[ImportModule, ...]:

    grouped = group_imports_by_module(imports)

    modules: list[ImportModule] = []

    for module_name, module_imports in grouped.items():
        ordered_imports = tuple(
            sorted(
                module_imports,
                key=lambda resolved: resolved.slot_va,
            )
        )

        modules.append(
            ImportModule(
                name=normalize_module_name(module_name),
                imports=ordered_imports,
            )
        )

    return tuple(modules)

def align_up(
    value: int,
    alignment: int,
) -> int:

    if alignment <= 0:
        raise ValueError("alignment must be greater than zero")

    return (value + alignment - 1) & ~(alignment - 1)

def calculate_layout(
    modules: tuple[ImportModule, ...],
    section_rva: int,
    pointer_size: int = 8,
) -> ImportLayout:

    if section_rva < 0:
        raise ValueError("section_rva cannot be negative")

    if pointer_size not in (4, 8):
        raise ValueError("pointer_size must be 4 or 8")

    descriptor_size = 20
    descriptor_table_size = (len(modules) + 1) * descriptor_size

    descriptor_rva = section_rva
    cursor = section_rva + descriptor_table_size

    #
    # DLL name strings.
    #
    dll_name_rvas: list[int] = []

    for module in modules:
        dll_name_rvas.append(cursor)

        encoded_name = module.name.encode("ascii")
        cursor += len(encoded_name) + 1

    #
    # IMAGE_IMPORT_BY_NAME structures.
    #
    import_name_rvas_by_module: list[tuple[int | None, ...]] = []

    for module in modules:
        module_name_rvas: list[int | None] = []

        for resolved in module.imports:
            if resolved.function_name is not None:
                cursor = align_up(cursor, 2)
                module_name_rvas.append(cursor)

                encoded_name = resolved.function_name.encode("ascii")

                #
                # IMAGE_IMPORT_BY_NAME:
                #
                # WORD Hint
                # CHAR Name[]
                #
                cursor += 2
                cursor += len(encoded_name) + 1

            elif resolved.ordinal is not None:
                module_name_rvas.append(None)

            else:
                raise ImportResolutionError(
                    f"Import at slot 0x{resolved.slot_va:X} "
                    "has neither a function name nor an ordinal"
                )

        import_name_rvas_by_module.append(
            tuple(module_name_rvas)
        )

    #
    # INT arrays.
    #
    cursor = align_up(cursor, pointer_size)

    int_rvas: list[int] = []
    int_sizes: list[int] = []

    for module in modules:
        int_rva = cursor
        int_size = (len(module.imports) + 1) * pointer_size

        int_rvas.append(int_rva)
        int_sizes.append(int_size)

        cursor += int_size

    #
    # IAT arrays.
    #
    cursor = align_up(cursor, pointer_size)

    iat_rvas: list[int] = []
    iat_sizes: list[int] = []

    for module in modules:
        iat_rva = cursor
        iat_size = (len(module.imports) + 1) * pointer_size

        iat_rvas.append(iat_rva)
        iat_sizes.append(iat_size)

        cursor += iat_size

    module_layouts: list[ImportModuleLayout] = []

    for index, module in enumerate(modules):
        module_layouts.append(
            ImportModuleLayout(
                module=module,
                descriptor_rva=descriptor_rva + (index * descriptor_size),
                dll_name_rva=dll_name_rvas[index],
                import_name_rvas=import_name_rvas_by_module[index],
                int_rva=int_rvas[index],
                iat_rva=iat_rvas[index],
                int_size=int_sizes[index],
                iat_size=iat_sizes[index],
            )
        )

    return ImportLayout(
        section_rva=section_rva,
        section_size=cursor - section_rva,
        descriptor_rva=descriptor_rva,
        descriptor_size=descriptor_table_size,
        modules=tuple(module_layouts),
    )

def build_import_section(
    layout: ImportLayout,
    pointer_size: int = 8,
) -> bytes:

    if pointer_size not in (4, 8):
        raise ValueError("pointer_size must be 4 or 8")

    data = bytearray(layout.section_size)

    if pointer_size == 8:
        thunk_format = "<Q"
        ordinal_flag = 0x8000000000000000
    else:
        thunk_format = "<I"
        ordinal_flag = 0x80000000

    def rva_to_offset(rva: int) -> int:
        offset = rva - layout.section_rva

        if offset < 0 or offset >= len(data):
            raise ValueError(
                f"RVA 0x{rva:X} falls outside import section"
            )

        return offset

    #
    # 1. Write IMAGE_IMPORT_DESCRIPTOR entries.
    #
    for module_layout in layout.modules:
        descriptor_offset = rva_to_offset(
            module_layout.descriptor_rva
        )

        struct.pack_into(
            "<IIIII",
            data,
            descriptor_offset,
            module_layout.int_rva,
            0,
            0,
            module_layout.dll_name_rva,
            module_layout.iat_rva,
        )

    #
    # The final IMAGE_IMPORT_DESCRIPTOR remains zero-filled.
    # bytearray() already initialized the section to zero.
    #

    #
    # 2. Write DLL name strings.
    #
    for module_layout in layout.modules:
        dll_name = module_layout.module.name.encode("ascii") + b"\x00"

        dll_name_offset = rva_to_offset(
            module_layout.dll_name_rva
        )

        data[
            dll_name_offset:
            dll_name_offset + len(dll_name)
        ] = dll_name

    #
    # 3. Write IMAGE_IMPORT_BY_NAME structures.
    #
    for module_layout in layout.modules:
        for resolved, name_rva in zip(
            module_layout.module.imports,
            module_layout.import_name_rvas,
        ):
            if name_rva is None:
                continue

            if resolved.function_name is None:
                raise ImportResolutionError(
                    f"Import at slot 0x{resolved.slot_va:X} "
                    "has an import-name RVA but no function name"
                )

            name_offset = rva_to_offset(
                name_rva
            )

            function_name = (
                resolved.function_name.encode("ascii")
                + b"\x00"
            )

            #
            # IMAGE_IMPORT_BY_NAME:
            #
            # WORD Hint = 0
            # CHAR Name[]
            #
            struct.pack_into(
                "<H",
                data,
                name_offset,
                0,
            )

            function_offset = name_offset + 2

            data[
                function_offset:
                function_offset + len(function_name)
            ] = function_name

    #
    # 4. Write INT and IAT thunk arrays.
    #
    for module_layout in layout.modules:
        int_offset = rva_to_offset(
            module_layout.int_rva
        )

        iat_offset = rva_to_offset(
            module_layout.iat_rva
        )

        for index, resolved in enumerate(
            module_layout.module.imports
        ):
            name_rva = (
                module_layout.import_name_rvas[index]
            )

            if name_rva is not None:
                thunk_value = name_rva

            elif resolved.ordinal is not None:
                thunk_value = (
                    ordinal_flag
                    | resolved.ordinal
                )

            else:
                raise ImportResolutionError(
                    f"Import at slot 0x{resolved.slot_va:X} "
                    "cannot be encoded"
                )

            struct.pack_into(
                thunk_format,
                data,
                int_offset + (index * pointer_size),
                thunk_value,
            )

            struct.pack_into(
                thunk_format,
                data,
                iat_offset + (index * pointer_size),
                thunk_value,
            )

        #
        # No explicit terminator is necessary.
        # The bytearray is zero-filled and calculate_layout()
        # reserved one additional thunk for each array.
        #

    return bytes(data)