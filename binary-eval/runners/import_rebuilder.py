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

from collections import defaultdict

from runners.import_resolver import ResolvedImport


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