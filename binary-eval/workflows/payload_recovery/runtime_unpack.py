# binary-eval/workflows/payload_recovery/runtime_unpack.py

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pefile

from runners.debugger import (
    CdbDebugger,
    DebuggerError,
    DirectJump,
    Instruction,
)


class RuntimeUnpackError(RuntimeError):
    pass


@dataclass(frozen=True)
class SectionRange:
    name: str
    rva: int
    virtual_size: int
    start_va: int
    end_va: int

    def contains(self, address: int) -> bool:
        return (
            self.start_va
            <= address
            < self.end_va
        )


@dataclass(frozen=True)
class UnpackResult:
    input_path: Path

    image_base: int

    packed_entry_va: int
    packed_entry_rva: int

    entry_rsp: int
    saved_rbx_slot: int

    stub_jump_va: int

    oep_va: int
    oep_rva: int

    source_section: str
    destination_section: str


class RuntimeUnpacker:
    """
    Deterministic runtime UPX recovery.

    Current invariant:

        packed EP
            -> push rbx
            -> watch saved RBX stack slot
            -> matching pop rbx
            -> direct JMP from stub into reconstructed section
            -> OEP
    """

    DEFAULT_DESTINATION_SECTIONS = (
        ".dst",
        "UPX0",
    )

    DEFAULT_STUB_SECTIONS = (
        ".stub",
        "UPX1",
    )

    def __init__(
        self,
        debugger: CdbDebugger,
        destination_sections: Iterable[str] | None = None,
        stub_sections: Iterable[str] | None = None,
        max_stack_watch_events: int = 8,
        max_post_restore_instructions: int = 16,
    ):
        self.debugger = debugger

        self.destination_sections = tuple(
            destination_sections
            or self.DEFAULT_DESTINATION_SECTIONS
        )

        self.stub_sections = tuple(
            stub_sections
            or self.DEFAULT_STUB_SECTIONS
        )

        self.max_stack_watch_events = (
            max_stack_watch_events
        )

        self.max_post_restore_instructions = (
            max_post_restore_instructions
        )

    # ------------------------------------------------------------------
    # Public workflow
    # ------------------------------------------------------------------

    def run(
        self,
        executable: Path | str,
    ) -> UnpackResult:

        executable = Path(executable)

        pe_info = self._parse_pe(
            executable
        )

        self.debugger.launch(
            executable
        )

        try:
            module = self.debugger.get_module(
                executable.name
            )

            image_base = module.base

            packed_entry_rva = (
                pe_info["entry_rva"]
            )

            packed_entry_va = (
                image_base
                + packed_entry_rva
            )

            sections = self._build_runtime_sections(
                pe_info=pe_info,
                image_base=image_base,
            )

            destination = self._find_section(
                sections,
                self.destination_sections,
            )

            stub = self._find_section(
                sections,
                self.stub_sections,
            )

            #
            # 1. Run to packed entry point.
            #
            self.debugger.set_breakpoint(
                packed_entry_va
            )

            self.debugger.continue_execution()

            rip = self.debugger.get_register(
                "rip"
            )

            if rip != packed_entry_va:
                raise RuntimeUnpackError(
                    "Did not stop at packed entry point: "
                    f"expected 0x{packed_entry_va:x}, "
                    f"got 0x{rip:x}"
                )

            #
            # 2. Verify packed EP begins with:
            #
            #       push rbx
            #
            entry_instruction = (
                self.debugger.disassemble_one(
                    packed_entry_va
                )
            )

            self._require_push_rbx(
                entry_instruction
            )

            #
            # 3. Record original RSP/RBX.
            #
            registers = (
                self.debugger.get_registers(
                    "rsp",
                    "rbx",
                )
            )

            entry_rsp = registers["rsp"]
            entry_rbx = registers["rbx"]

            #
            # The software entry breakpoint is no longer needed.
            #
            self.debugger.clear_all_breakpoints()

            #
            # 4. Execute push rbx.
            #
            self.debugger.step_into()

            new_rsp = self.debugger.get_register(
                "rsp"
            )

            expected_rsp = entry_rsp - 8

            if new_rsp != expected_rsp:
                raise RuntimeUnpackError(
                    "push rbx did not produce expected RSP: "
                    f"expected 0x{expected_rsp:x}, "
                    f"got 0x{new_rsp:x}"
                )

            saved_rbx_slot = new_rsp

            #
            # Verify the qword at [new RSP] contains the
            # RBX value that was pushed.
            #
            saved_value = self.debugger.read_qword(
                saved_rbx_slot
            )

            if saved_value != entry_rbx:
                raise RuntimeUnpackError(
                    "Saved RBX stack value does not match "
                    "entry RBX: "
                    f"expected 0x{entry_rbx:x}, "
                    f"got 0x{saved_value:x}"
                )

            #
            # 5. Hardware read/write breakpoint over the
            #    saved RBX qword.
            #
            self.debugger.set_access_breakpoint(
                address=saved_rbx_slot,
                size=8,
            )

            #
            # 6. Continue until we identify the matching
            #    outer pop rbx.
            #
            restore_rip = (
                self._wait_for_outer_rbx_restore(
                    entry_rsp=entry_rsp,
                    entry_rbx=entry_rbx,
                )
            )

            #
            # The saved-RBX hardware watchpoint has served
            # its purpose. Remove it before continuing
            # through the rest of the stub.
            #
            self.debugger.clear_all_breakpoints()

            #
            # We're now stopped immediately AFTER pop rbx.
            #
            # RIP points at the next instruction.
            #
            # 7. Find the following direct relative JMP
            #    from the stub into the reconstructed section.
            #
            jump = self._find_stub_exit_jump(
                start_va=restore_rip,
                stub=stub,
                destination=destination,
            )

            #
            # 8. Break directly on the stub-exit JMP and
            #    continue until that exact instruction.
            #
            self.debugger.set_breakpoint(
                jump.source
            )

            self.debugger.continue_execution()

            current_rip = (
                self.debugger.get_register(
                    "rip"
                )
            )

            #
            # Temporary diagnostic output.
            #
            print(
                f"[debug] Expected stub-exit JMP: "
                f"0x{jump.source:x}"
            )

            print(
                f"[debug] Current RIP after continue: "
                f"0x{current_rip:x}"
            )

            for instruction in (
                self.debugger.iter_instructions(
                    current_rip,
                    max_instructions=8,
                )
            ):
                print(
                    f"[debug] {instruction.text}"
                )

            if current_rip != jump.source:
                raise RuntimeUnpackError(
                    "Did not stop at stub exit JMP: "
                    f"expected 0x{jump.source:x}, "
                    f"got 0x{current_rip:x}"
                )

            #
            # 9. Validate the live instruction at the
            #    breakpoint.
            #
            live_jump_instruction = (
                self.debugger.disassemble_one(
                    current_rip
                )
            )

            live_jump = (
                self.debugger.resolve_direct_jump(
                    live_jump_instruction
                )
            )

            if live_jump is None:
                raise RuntimeUnpackError(
                    f"Instruction at 0x{current_rip:x} "
                    "is not a direct JMP"
                )

            if live_jump.target != jump.target:
                raise RuntimeUnpackError(
                    "JMP target changed unexpectedly: "
                    f"expected 0x{jump.target:x}, "
                    f"got 0x{live_jump.target:x}"
                )

            #
            # 10. Execute exactly the stub-exit JMP.
            #
            self.debugger.step_into()

            oep_va = self.debugger.get_register(
                "rip"
            )

            #
            # 11. Verify that execution landed at the
            #     expected OEP candidate.
            #
            if oep_va != jump.target:
                raise RuntimeUnpackError(
                    "JMP did not land on expected OEP: "
                    f"expected 0x{jump.target:x}, "
                    f"got 0x{oep_va:x}"
                )

            if not destination.contains(
                oep_va
            ):
                raise RuntimeUnpackError(
                    "OEP does not lie inside reconstructed "
                    f"section {destination.name}: "
                    f"0x{oep_va:x}"
                )

            #
            # RVA is relative to the loaded image base,
            # NOT the reconstructed section base.
            #
            oep_rva = (
                oep_va
                - image_base
            )

            #
            # Leave CDB paused on the confirmed OEP.
            #
            return UnpackResult(
                input_path=executable,

                image_base=image_base,

                packed_entry_va=packed_entry_va,
                packed_entry_rva=packed_entry_rva,

                entry_rsp=entry_rsp,
                saved_rbx_slot=saved_rbx_slot,

                stub_jump_va=jump.source,

                oep_va=oep_va,
                oep_rva=oep_rva,

                source_section=stub.name,
                destination_section=destination.name,
            )

        except Exception:
            self.debugger.close()
            raise

    # ------------------------------------------------------------------
    # Sentinel restoration
    # ------------------------------------------------------------------

    def _wait_for_outer_rbx_restore(
        self,
        entry_rsp: int,
        entry_rbx: int,
    ) -> int:

        for _ in range(
            self.max_stack_watch_events
        ):
            self.debugger.continue_execution()

            rip = self.debugger.get_register(
                "rip"
            )

            rsp = self.debugger.get_register(
                "rsp"
            )

            rbx = self.debugger.get_register(
                "rbx"
            )

            try:
                previous = (
                    self.debugger.disassemble_previous(
                        rip
                    )
                )

            except DebuggerError:
                previous = None

            #
            # Hardware data breakpoints on x86/x64 fire
            # after the memory-accessing instruction.
            #
            # Therefore, after the matching:
            #
            #       pop rbx
            #
            # we expect:
            #
            #       RIP = next instruction
            #       RSP = original entry RSP
            #       RBX = original entry RBX
            #
            if (
                previous is not None
                and self._is_pop_rbx(previous)
                and rsp == entry_rsp
                and rbx == entry_rbx
            ):
                return rip

            #
            # Some other instruction touched the sentinel.
            # Keep watching.
            #

        raise RuntimeUnpackError(
            "Saved RBX slot was accessed, but no matching "
            "outer pop rbx was identified"
        )

    # ------------------------------------------------------------------
    # Locate stub exit JMP
    # ------------------------------------------------------------------

    def _find_stub_exit_jump(
        self,
        start_va: int,
        stub: SectionRange,
        destination: SectionRange,
    ) -> DirectJump:

        for instruction in (
            self.debugger.iter_instructions(
                start_va,
                max_instructions=(
                    self.max_post_restore_instructions
                ),
            )
        ):

            jump = (
                self.debugger.resolve_direct_jump(
                    instruction
                )
            )

            if jump is None:
                continue

            #
            # Required transition:
            #
            #       .stub / UPX1
            #              ↓
            #       .dst / UPX0
            #
            if (
                stub.contains(jump.source)
                and destination.contains(
                    jump.target
                )
            ):
                return jump

        raise RuntimeUnpackError(
            "Could not locate direct stub-to-destination "
            "JMP after the RBX restore"
        )

    # ------------------------------------------------------------------
    # Instruction validation
    # ------------------------------------------------------------------

    @staticmethod
    def _require_push_rbx(
        instruction: Instruction,
    ) -> None:

        operands = (
            instruction.operands
            .lower()
            .replace(" ", "")
        )

        if (
            instruction.mnemonic != "push"
            or operands != "rbx"
        ):
            raise RuntimeUnpackError(
                "Packed entry point does not begin with "
                f"'push rbx': {instruction.text}"
            )

    @staticmethod
    def _is_pop_rbx(
        instruction: Instruction,
    ) -> bool:

        operands = (
            instruction.operands
            .lower()
            .replace(" ", "")
        )

        return (
            instruction.mnemonic == "pop"
            and operands == "rbx"
        )

    # ------------------------------------------------------------------
    # PE parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_pe(
        path: Path,
    ) -> dict:

        pe = pefile.PE(
            str(path),
            fast_load=True,
        )

        try:
            sections = []

            for section in pe.sections:
                name = (
                    section.Name
                    .rstrip(b"\x00")
                    .decode(
                        "ascii",
                        errors="replace",
                    )
                )

                virtual_size = (
                    section.Misc_VirtualSize
                    or section.SizeOfRawData
                )

                sections.append(
                    {
                        "name": name,
                        "rva": (
                            section.VirtualAddress
                        ),
                        "virtual_size": (
                            virtual_size
                        ),
                    }
                )

            return {
                "entry_rva": (
                    pe.OPTIONAL_HEADER
                    .AddressOfEntryPoint
                ),
                "section_alignment": (
                    pe.OPTIONAL_HEADER
                    .SectionAlignment
                ),
                "sections": sections,
            }

        finally:
            pe.close()

    def _build_runtime_sections(
        self,
        pe_info: dict,
        image_base: int,
    ) -> list[SectionRange]:

        alignment = pe_info[
            "section_alignment"
        ]

        result = []

        for section in pe_info["sections"]:
            size = self._align_up(
                section["virtual_size"],
                alignment,
            )

            start = (
                image_base
                + section["rva"]
            )

            result.append(
                SectionRange(
                    name=section["name"],
                    rva=section["rva"],
                    virtual_size=size,
                    start_va=start,
                    end_va=start + size,
                )
            )

        return result

    @staticmethod
    def _find_section(
        sections: list[SectionRange],
        candidates: tuple[str, ...],
    ) -> SectionRange:

        candidate_names = {
            name.lower()
            for name in candidates
        }

        for section in sections:
            if (
                section.name.lower()
                in candidate_names
            ):
                return section

        available = ", ".join(
            section.name
            for section in sections
        )

        raise RuntimeUnpackError(
            "Could not find expected section "
            f"{candidates}. Available: {available}"
        )

    @staticmethod
    def _align_up(
        value: int,
        alignment: int,
    ) -> int:

        if alignment == 0:
            return value

        return (
            value
            + alignment
            - 1
        ) & ~(alignment - 1)