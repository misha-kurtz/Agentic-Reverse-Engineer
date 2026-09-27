# binary-eval/runners/import_resolver.py
from __future__ import annotations

from dataclasses import dataclass

from runners.debugger import ModuleInfo
from runners.iat import Thunk, ThunkStatus


class ImportResolutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ResolvedImport:
    slot_va: int
    target_va: int

    module_name: str

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

        #
        # Export lookup comes next.
        #
        function_name = None
        ordinal = None

        return ResolvedImport(
            slot_va=thunk.slot_va,
            target_va=thunk.target_va,
            module_name=module.name,
            function_name=function_name,
            ordinal=ordinal,
        )