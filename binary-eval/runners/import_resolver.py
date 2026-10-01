# binary-eval/runners/import_resolver.py

'''
import_resolver.py
    raw thunk
        ↓
    ResolvedImport
        - slot_va
        - target_va
        - module_name
        - target_rva
        - function_name
        - ordinal
'''

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pefile

from runners.debugger import ModuleInfo
from runners.iat import Thunk, ThunkStatus


class ImportResolutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ResolvedImport:
    slot_va: int
    target_va: int

    module_name: str
    target_rva: int

    function_name: str | None
    ordinal: int | None

    @property
    def resolved_by_name(self) -> bool:
        return self.function_name is not None


class ImportResolver:
    def __init__(
        self,
        modules: tuple[ModuleInfo, ...],
    ):
        self.modules = modules

        self._exports: dict[
            str,
            dict[int, tuple[str | None, int]]
        ] = {}

    def find_module(
        self,
        target_va: int,
    ) -> ModuleInfo | None:

        for module in self.modules:
            if module.base <= target_va < module.end:
                return module

        return None

    def resolve_thunk(
        self,
        thunk: Thunk,
    ) -> ResolvedImport:

        if thunk.status != ThunkStatus.VALID_EXTERNAL:
            raise ImportResolutionError(
                f"Thunk at 0x{thunk.slot_va:X} "
                "is not a valid external thunk"
            )

        module = self.find_module(
            thunk.target_va
        )

        if module is None:
            raise ImportResolutionError(
                f"No loaded module contains "
                f"target 0x{thunk.target_va:X}"
            )

        target_rva = (
            thunk.target_va
            - module.base
        )

        module_path = self._resolve_module_path(
            module
        )

        export_map = self._load_exports(
            module,
            module_path,
        )

        export = export_map.get(
            target_rva
        )

        if export is None:
            function_name = None
            ordinal = None
        else:
            function_name, ordinal = export

        return ResolvedImport(
            slot_va=thunk.slot_va,
            target_va=thunk.target_va,
            module_name=module.name,
            target_rva=target_rva,
            function_name=function_name,
            ordinal=ordinal,
        )

    def _load_exports(
        self,
        module: ModuleInfo,
        module_path: str | Path,
    ) -> dict[int, tuple[str | None, int]]:

        module_key = module.name.lower()

        cached = self._exports.get(
            module_key
        )

        if cached is not None:
            return cached

        module_path = Path(
            module_path
        )

        if not module_path.exists():
            raise ImportResolutionError(
                f"Module file does not exist: "
                f"{module_path}"
            )

        try:
            pe = pefile.PE(
                str(module_path),
                fast_load=False,
            )
        except pefile.PEFormatError as exc:
            raise ImportResolutionError(
                f"Unable to parse exports from "
                f"{module_path}"
            ) from exc

        exports: dict[
            int,
            tuple[str | None, int]
        ] = {}

        if not hasattr(
            pe,
            "DIRECTORY_ENTRY_EXPORT",
        ):
            pe.close()

            self._exports[
                module_key
            ] = exports

            return exports

        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:

            export_rva = symbol.address

            if symbol.name is None:
                function_name = None
            else:
                function_name = symbol.name.decode(
                    errors="replace"
                )

            exports[
                export_rva
            ] = (
                function_name,
                symbol.ordinal,
            )

        pe.close()

        self._exports[
            module_key
        ] = exports

        return exports

    def _resolve_module_path(
        self,
        module: ModuleInfo,
    ) -> Path:

        module_name = module.name

        if not module_name.lower().endswith(".dll"):
            module_name += ".dll"

        candidates = (
            Path(r"C:\Windows\System32") / module_name,
            Path(r"C:\Windows\SysWOW64") / module_name,
        )

        for candidate in candidates:
            if candidate.exists():
                return candidate

        raise ImportResolutionError(
            f"Unable to locate module file for "
            f"{module.name}"
        )
