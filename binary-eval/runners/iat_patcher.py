# binary-eval/runners/iat_patcher.py

from __future__ import annotations
from dataclasses import dataclass
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

from runners.import_rebuilder import IATRelocation


class IATPatchError(RuntimeError):
    pass


@dataclass(frozen=True)
class IATReferencePatch:
    instruction_rva: int
    instruction_size: int

    old_slot_rva: int
    new_slot_rva: int

    displacement_offset: int
    old_displacement: int
    new_displacement: int

    module_name: str
    function_name: str | None
    ordinal: int | None


@dataclass(frozen=True)
class IATPatchResult:
    patches: tuple[IATReferencePatch, ...]
    referenced_slots: tuple[int, ...]

    @property
    def patch_count(self) -> int:
        return len(self.patches)

    @property
    def referenced_slot_count(self) -> int:
        return len(self.referenced_slots)


class IATReferencePatcher:
    def __init__(
        self,
        pe: pefile.PE,
    ):
        self.pe = pe

        self.disassembler = Cs(
            CS_ARCH_X86,
            CS_MODE_64,
        )

        self.disassembler.detail = True

        #
        # Continue disassembly across embedded data or
        # otherwise undecodable bytes in executable sections.
        #
        self.disassembler.skipdata = True

    # Scan only executable sections
    def _is_executable(
        self,
        section,
    ) -> bool:

        return bool(
            section.Characteristics
            & 0x20000000  # IMAGE_SCN_MEM_EXECUTE = 0x20000000
        )

    # Find RIP-relative references 
    def patch(
        self,
        output_data: bytearray,
        relocations: tuple[IATRelocation, ...],
    ) -> IATPatchResult:

        relocation_map = {
            relocation.old_slot_rva: relocation
            for relocation in relocations
        }

        patches: list[IATReferencePatch] = []
        referenced_slots: set[int] = set()

        for section in self.pe.sections:
            if not self._is_executable(section):
                continue

            section_rva = (
                section.VirtualAddress
            )

            section_raw_offset = (
                section.PointerToRawData
            )

            section_raw_size = (
                section.SizeOfRawData
            )

            if section_raw_size == 0:
                continue

            section_end = (
                section_raw_offset
                + section_raw_size
            )

            if section_end > len(output_data):
                raise IATPatchError(
                    "Executable section extends beyond "
                    "reconstructed file"
                )

            section_data = bytes(
                output_data[
                    section_raw_offset:
                    section_end
                ]
            )

            for instruction in (
                self.disassembler.disasm(
                    section_data,
                    section_rva,
                )
            ):
                self._patch_instruction(
                    output_data=output_data,
                    instruction=instruction,
                    section_rva=section_rva,
                    section_raw_offset=section_raw_offset,
                    relocation_map=relocation_map,
                    patches=patches,
                    referenced_slots=referenced_slots,
                )

        return IATPatchResult(
            patches=tuple(patches),
            referenced_slots=tuple(
                sorted(referenced_slots)
            ),
        )


    # Examine each instruction's memory operands
    def _patch_instruction(
        self,
        output_data: bytearray,
        instruction,
        section_rva: int,
        section_raw_offset: int,
        relocation_map: dict[int, IATRelocation],
        patches: list[IATReferencePatch],
        referenced_slots: set[int],
    ) -> None:

        #
        # Capstone skip-data entries represent raw bytes,
        # not real decoded instructions.
        #
        if instruction.id == 0:
            return

        for operand in instruction.operands:
            if operand.type != X86_OP_MEM:
                continue

            memory = operand.mem

            if memory.base != X86_REG_RIP:
                continue

            old_target_rva = (
                instruction.address
                + instruction.size
                + memory.disp
            )

            relocation = relocation_map.get(
                old_target_rva
            )

            if relocation is None:
                continue

            self._apply_patch(
                output_data=output_data,
                instruction=instruction,
                section_rva=section_rva,
                section_raw_offset=section_raw_offset,
                relocation=relocation,
                patches=patches,
            )

            referenced_slots.add(
                relocation.old_slot_rva
            )

            break

    def _apply_patch(
        self,
        output_data: bytearray,
        instruction,
        section_rva: int,
        section_raw_offset: int,
        relocation: IATRelocation,
        patches: list[IATReferencePatch],
    ) -> None:

        # Calculate new displacement for instruction
        displacement_offset = (
            instruction.disp_offset
        )

        displacement_size = (
            instruction.disp_size
        )

        if displacement_size != 4:
            raise IATPatchError(
                f"Unsupported displacement size "
                f"{displacement_size} at "
                f"RVA 0x{instruction.address:X}"
            )

        next_instruction_rva = (
            instruction.address
            + instruction.size
        )

        new_displacement = (
            relocation.new_slot_rva
            - next_instruction_rva
        )

        if not (
            -0x80000000
            <= new_displacement
            <= 0x7FFFFFFF
        ):
            raise IATPatchError(
                f"New IAT reference from "
                f"RVA 0x{instruction.address:X} "
                "does not fit in disp32"
            )

        # Determine where instruction exists on disk
        instruction_offset_in_section = (
            instruction.address
            - section_rva
        )

        instruction_file_offset = (
            section_raw_offset
            + instruction_offset_in_section
        )

        patch_file_offset = (
            instruction_file_offset
            + displacement_offset
        )

        # Save old displacement
        old_displacement = struct.unpack_from(
            "<i",
            output_data,
            patch_file_offset,
        )[0]

        # Patch the new displacement into instruction
        struct.pack_into(
            "<i",
            output_data,
            patch_file_offset,
            new_displacement,
        )

        # Record what happened
        patches.append(
            IATReferencePatch(
                instruction_rva=instruction.address,
                instruction_size=instruction.size,
                old_slot_rva=relocation.old_slot_rva,
                new_slot_rva=relocation.new_slot_rva,
                displacement_offset=displacement_offset,
                old_displacement=old_displacement,
                new_displacement=new_displacement,
                module_name=relocation.module_name,
                function_name=relocation.function_name,
                ordinal=relocation.ordinal,
            )
        )