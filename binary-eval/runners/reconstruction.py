# binary-eval/runners/reconstruction.py

'''
Reconstruct the Portable Executable from memory

memory dump
+ original PE metadata
+ image base
+ OEP RVA
+ selected IAT
        ↓
recovered.exe
'''

# binary-eval/runners/reconstruction.py

from __future__ import annotations

import struct

from dataclasses import dataclass
from pathlib import Path

import pefile


class ReconstructionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReconstructedSection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclass(frozen=True)
class ReconstructionResult:
    input_path: Path
    output_path: Path

    original_oep_rva: int
    recovered_oep_rva: int

    file_alignment: int
    section_alignment: int

    sections: tuple[ReconstructedSection, ...]

    @property
    def output_size(self) -> int:
        return self.output_path.stat().st_size


class PEReconstructor:
    '''
    Convert a mapped PE memory image into a disk-layout PE.

    This stage:
        - preserves the PE headers
        - patches AddressOfEntryPoint
        - assigns new raw offsets to each section
        - copies section contents from RVA-based memory layout
        - updates SizeOfRawData / PointerToRawData

    Import reconstruction is intentionally handled separately.
    '''

    def __init__(
        self,
        memory_dump_path: Path | str,
    ):
        self.memory_dump_path = Path(
            memory_dump_path
        ).resolve()

        if not self.memory_dump_path.exists():
            raise ReconstructionError(
                f"Memory dump does not exist: "
                f"{self.memory_dump_path}"
            )

        self.memory_data = (
            self.memory_dump_path.read_bytes()
        )

        try:
            self.pe = pefile.PE(
                data=self.memory_data,
                fast_load=False,
            )
        except pefile.PEFormatError as exc:
            raise ReconstructionError(
                "Unable to parse PE headers from "
                f"{self.memory_dump_path}"
            ) from exc

    @staticmethod
    def _align(
        value: int,
        alignment: int,
    ) -> int:

        if alignment <= 0:
            raise ValueError(
                "alignment must be greater than zero"
            )

        return (
            value + alignment - 1
        ) & ~(alignment - 1)

    def _validate_oep(
        self,
        oep_rva: int,
    ) -> None:

        size_of_image = (
            self.pe.OPTIONAL_HEADER.SizeOfImage
        )

        if not (
            0 <= oep_rva < size_of_image
        ):
            raise ReconstructionError(
                f"Recovered OEP RVA 0x{oep_rva:X} "
                f"is outside image size "
                f"0x{size_of_image:X}"
            )

        for section in self.pe.sections:
            start = section.VirtualAddress

            end = (
                start
                + max(
                    section.Misc_VirtualSize,
                    section.SizeOfRawData,
                )
            )

            if start <= oep_rva < end:
                return

        raise ReconstructionError(
            f"Recovered OEP RVA 0x{oep_rva:X} "
            "does not fall inside any PE section"
        )

    def reconstruct(
        self,
        output_path: Path | str,
        oep_rva: int,
    ) -> ReconstructionResult:

        output_path = Path(
            output_path
        ).resolve()

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._validate_oep(
            oep_rva
        )

        file_alignment = (
            self.pe.OPTIONAL_HEADER.FileAlignment
        )

        section_alignment = (
            self.pe.OPTIONAL_HEADER.SectionAlignment
        )

        original_oep = (
            self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        )

        #
        # Start the first section after the PE headers.
        #
        header_size = self._align(
            self.pe.OPTIONAL_HEADER.SizeOfHeaders,
            file_alignment,
        )

        if header_size > len(self.memory_data):
            raise ReconstructionError(
                "SizeOfHeaders extends beyond "
                "the memory dump"
            )

        reconstructed_sections: list[
            ReconstructedSection
        ] = []

        current_raw_offset = header_size

        #
        # Determine the new raw layout.
        #
        for section in self.pe.sections:
            name = section.Name.rstrip(
                b"\x00"
            ).decode(
                errors="replace"
            )

            virtual_size = (
                section.Misc_VirtualSize
            )

            if virtual_size == 0:
                raw_size = 0
            else:
                raw_size = self._align(
                    virtual_size,
                    file_alignment,
                )

            reconstructed_sections.append(
                ReconstructedSection(
                    name=name,
                    virtual_address=(
                        section.VirtualAddress
                    ),
                    virtual_size=virtual_size,
                    raw_offset=current_raw_offset,
                    raw_size=raw_size,
                )
            )

            current_raw_offset += raw_size

        #
        # Allocate the reconstructed disk image.
        #
        output_data = bytearray(
            current_raw_offset
        )

        #
        # Preserve the existing PE headers.
        #
        output_data[
            :header_size
        ] = self.memory_data[
            :header_size
        ]

        #
        # Copy mapped section contents from:
        #
        #     memory offset == section RVA
        #
        # into the new disk-layout raw offsets.
        #
        for section_info in reconstructed_sections:

            if section_info.raw_size == 0:
                continue

            source_start = (
                section_info.virtual_address
            )

            source_end = (
                source_start
                + section_info.virtual_size
            )

            if source_end > len(
                self.memory_data
            ):
                raise ReconstructionError(
                    f"Section {section_info.name} "
                    f"extends beyond memory dump: "
                    f"RVA 0x{source_start:X}-"
                    f"0x{source_end:X}"
                )

            destination_start = (
                section_info.raw_offset
            )

            destination_end = (
                destination_start
                + section_info.virtual_size
            )

            output_data[
                destination_start:
                destination_end
            ] = self.memory_data[
                source_start:
                source_end
            ]

        #
        # Patch AddressOfEntryPoint.
        #
        oep_offset = (
            self.pe.OPTIONAL_HEADER
            .get_field_absolute_offset(
                "AddressOfEntryPoint"
            )
        )

        struct.pack_into(
            "<I",
            output_data,
            oep_offset,
            oep_rva,
        )

        #
        # Update SizeOfHeaders in case alignment
        # changed its effective disk size.
        #
        size_of_headers_offset = (
            self.pe.OPTIONAL_HEADER
            .get_field_absolute_offset(
                "SizeOfHeaders"
            )
        )

        struct.pack_into(
            "<I",
            output_data,
            size_of_headers_offset,
            header_size,
        )

        #
        # Patch each section header with its new
        # disk-layout information.
        #
        for section, section_info in zip(
            self.pe.sections,
            reconstructed_sections,
        ):
            raw_size_offset = (
                section.get_field_absolute_offset(
                    "SizeOfRawData"
                )
            )

            raw_pointer_offset = (
                section.get_field_absolute_offset(
                    "PointerToRawData"
                )
            )

            struct.pack_into(
                "<I",
                output_data,
                raw_size_offset,
                section_info.raw_size,
            )

            struct.pack_into(
                "<I",
                output_data,
                raw_pointer_offset,
                section_info.raw_offset,
            )

        output_path.write_bytes(
            output_data
        )

        #
        # Final structural validation.
        #
        try:
            rebuilt = pefile.PE(
                str(output_path),
                fast_load=False,
            )
        except pefile.PEFormatError as exc:
            raise ReconstructionError(
                "Reconstructed file could not "
                "be parsed as a PE"
            ) from exc

        if (
            rebuilt.OPTIONAL_HEADER
            .AddressOfEntryPoint
            != oep_rva
        ):
            raise ReconstructionError(
                "Reconstructed PE contains an "
                "incorrect entry point"
            )

        rebuilt.close()

        return ReconstructionResult(
            input_path=self.memory_dump_path,
            output_path=output_path,
            original_oep_rva=original_oep,
            recovered_oep_rva=oep_rva,
            file_alignment=file_alignment,
            section_alignment=section_alignment,
            sections=tuple(
                reconstructed_sections
            ),
        )