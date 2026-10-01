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
from dataclasses import dataclass
from __future__ import annotations

from collections import defaultdict

from runners.import_resolver import ResolvedImport

@dataclass(frozen=True)
class ImportModule:
    name: str
    imports: tuple[ResolvedImport, ...]

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
                name=module_name,
                imports=ordered_imports,
            )
        )

    return tuple(modules)
