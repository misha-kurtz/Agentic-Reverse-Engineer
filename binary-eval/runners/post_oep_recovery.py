# binary-eval/runners/post_oep_recovery.py

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from runners.debugger import CdbDebugger, ModuleInfo
from runners.iat import IATAnalyzer, IATAnalysisResult, Thunk
from runners.import_resolver import ImportResolver, ResolvedImport
from runners.import_rebuilder import build_import_modules
from runners.memory_dump import MemoryDumper
from runners.reconstruction import PEReconstructor, ReconstructionResult


class PostOEPRecoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class PostOEPRecoveryResult:
    image_base: int
    image_size: int

    oep_va: int
    oep_rva: int

    iat_start_va: int
    iat_size: int

    iat_valid_thunks: int
    iat_invalid_thunks: int

    iat_thunks: tuple[Thunk, ...]
    iat_analysis: IATAnalysisResult

    resolved_imports: tuple[ResolvedImport, ...]
    loaded_modules: tuple[ModuleInfo, ...]

    dump_path: Path
    reconstructed_path: Path | None

    reconstruction: ReconstructionResult | None

    @property
    def iat_rva(self) -> int:
        return self.iat_start_va - self.image_base


class PostOEPRecovery:
    """
    Shared Scylla-like recovery workflow.

    Preconditions:
        - CDB is paused at the recovered OEP.
        - The reconstructed PE is mapped in process memory.
        - The recovered image base and SizeOfImage are known.

    The debugger remains paused at the OEP.
    """

    def __init__(self, debugger: CdbDebugger):
        self.debugger = debugger

    def run(
        self,
        image_base: int,
        image_size: int,
        oep_rva: int,
        dump_path: Path | str,
        reconstructed_path: Path | str | None = None,
        packed_entry_rva: int | None = None,
        stub_jump_rva: int | None = None,
    ) -> PostOEPRecoveryResult:

        if image_base <= 0 or image_size <= 0:
            raise PostOEPRecoveryError("Invalid recovered image range")

        if not 0 <= oep_rva < image_size:
            raise PostOEPRecoveryError("OEP RVA is outside recovered image")

        oep_va = image_base + oep_rva

        current_rip = self.debugger.get_register("rip")

        if current_rip != oep_va:
            raise PostOEPRecoveryError(
                f"Debugger is not paused at OEP: "
                f"expected 0x{oep_va:X}, got 0x{current_rip:X}"
            )

        print("\n=== POST-OEP RECOVERY ===")
        print(f"[post-oep] Image base: 0x{image_base:X}")
        print(f"[post-oep] Image size: 0x{image_size:X}")
        print(f"[post-oep] OEP: 0x{oep_va:X}")

        # --------------------------------------------------
        # Stage 1: Loaded-module enumeration
        # --------------------------------------------------

        loaded_modules = tuple(self.debugger.get_modules())

        print(f"\n[post-oep] Loaded modules: {len(loaded_modules)}")

        # --------------------------------------------------
        # Stage 2: IAT discovery
        # --------------------------------------------------

        analyzer = IATAnalyzer(
            debugger=self.debugger,
            image_start=image_base,
            image_end=image_base + image_size,
            modules=loaded_modules,
            pointer_size=8,
        )

        iat_analysis = analyzer.discover_and_analyze()
        selected_iat = iat_analysis.selected

        print("\n=== IAT ANALYSIS ===")
        print(analyzer.format_analysis_result(iat_analysis))

        print("\n[iat] Invalid thunks:")
        print(
            analyzer.format_thunks(
                selected_iat,
                include_valid=False,
                include_invalid=True,
                include_null=False,
            )
        )

        # --------------------------------------------------
        # Stage 3: Prune invalid thunks
        # --------------------------------------------------

        valid_thunks = analyzer.prune_invalid_thunks(selected_iat)

        print(f"\n[iat] Selected: {selected_iat.name}")
        print(f"[iat] Start: 0x{selected_iat.start_va:X}")
        print(f"[iat] Size: 0x{selected_iat.size:X}")
        print(f"[iat] Valid thunks: {len(valid_thunks)}")
        print(f"[iat] Invalid thunks: {selected_iat.invalid_total}")

        # --------------------------------------------------
        # Stage 4: Resolve imports
        # --------------------------------------------------

        resolver = ImportResolver(loaded_modules)
        resolved_imports = []

        for thunk in valid_thunks:
            resolved = resolver.resolve_thunk(thunk)
            resolved_imports.append(resolved)

            name = resolved.function_name

            if name is None:
                name = f"ordinal_{resolved.ordinal}"

            print(f"[import] {resolved.module_name}!{name}")

        resolved_imports = tuple(resolved_imports)

        # --------------------------------------------------
        # Stage 5: Memory dump
        # --------------------------------------------------

        dump_path = Path(dump_path)

        dumper = MemoryDumper(self.debugger)

        memory_dump = dumper.dump_image(
            output_path=dump_path,
            start_va=image_base,
            end_va=image_base + image_size,
        )

        print("\n=== MEMORY DUMP ===")
        print(f"[dump] Path: {memory_dump.path}")
        print(f"[dump] Size: 0x{memory_dump.size:X}")

        # --------------------------------------------------
        # Stage 6: PE reconstruction
        # --------------------------------------------------

        reconstruction = None
        output_path = None

        if reconstructed_path is not None:
            if not resolved_imports:
                raise PostOEPRecoveryError(
                    "Cannot rebuild imports: no imports were resolved"
                )

            output_path = Path(reconstructed_path)

            import_modules = build_import_modules(list(resolved_imports))

            reconstructor = PEReconstructor(memory_dump.path)

            reconstruction = reconstructor.reconstruct(
                output_path=output_path,
                oep_rva=oep_rva,
                import_modules=import_modules,
                runtime_image_base=image_base,
                packed_entry_rva=packed_entry_rva,
                stub_jump_rva=stub_jump_rva,
            )

            print("\n=== PE RECONSTRUCTION ===")
            print(f"[reconstruction] Output: {reconstruction.output_path}")
            print(f"[reconstruction] Size: {reconstruction.output_size}")

        # --------------------------------------------------
        # Stage 7: Verify debugger remains at OEP
        # --------------------------------------------------

        final_rip = self.debugger.get_register("rip")

        if final_rip != oep_va:
            raise PostOEPRecoveryError(
                f"Debugger moved from OEP: 0x{final_rip:X}"
            )

        print(f"\n[post-oep] CDB remains paused at 0x{final_rip:X}")

        return PostOEPRecoveryResult(
            image_base=image_base,
            image_size=image_size,
            oep_va=oep_va,
            oep_rva=oep_rva,
            iat_start_va=selected_iat.start_va,
            iat_size=selected_iat.size,
            iat_valid_thunks=selected_iat.valid_external,
            iat_invalid_thunks=selected_iat.invalid_total,
            iat_thunks=selected_iat.thunks,
            iat_analysis=iat_analysis,
            resolved_imports=resolved_imports,
            loaded_modules=loaded_modules,
            dump_path=memory_dump.path,
            reconstructed_path=output_path,
            reconstruction=reconstruction,
        )