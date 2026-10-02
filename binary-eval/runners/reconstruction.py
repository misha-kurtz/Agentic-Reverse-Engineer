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

from runners.import_rebuilder import (
    ImportLayout,
    ImportModule,
    build_import_section,
    calculate_layout,
)


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

    # Determine RVA of .scy section 
    def _get_next_section_rva(
        self,
        section_alignment: int,
    ) -> int:

        if not self.pe.sections:
            raise ReconstructionError(
                "PE contains no sections"
            )

        last_section = self.pe.sections[-1]

        last_section_end = (
            last_section.VirtualAddress
            + max(
                last_section.Misc_VirtualSize,
                last_section.SizeOfRawData,
            )
        )

        return self._align(
            last_section_end,
            section_alignment,
        )

    # Update the import directory in the reconstructed PE file.
    # So Windows/PE parsers know Import Directory -> .scy descriptor array
    def update_import_directory(
        self,
        output_data: bytearray,
        import_rva: int,
        import_size: int,
    ) -> None:

        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ]

        directory_offset = directory.get_file_offset()

        struct.pack_into(
            "<II",
            output_data,
            directory_offset,
            import_rva,
            import_size,
        )

    def add_import_section(
        self,
        output_data: bytearray,
        section_data: bytes,
        section_rva: int,
        file_alignment: int,
        section_alignment: int,
        section_name: bytes = b".scy",
    ) -> ReconstructedSection:
        '''
        calculate raw placement
        extend output_data
        write .scy contents
        write IMAGE_SECTION_HEADER
        increment NumberOfSections
        update SizeOfImage
        '''

        # Validate import section data and name
        if not section_data:
            raise ReconstructionError(
                "Import section data is empty"
            )

        if len(section_name) > 8:
            raise ReconstructionError(
                "PE section names cannot exceed 8 bytes"
            )

        virtual_size = len(section_data)

        raw_size = self._align(
            virtual_size,
            file_alignment,
        )

        raw_offset = self._align(
            len(output_data),
            file_alignment,
        )

        # Ensure bytearray is large enough to hold new section
        required_size = (
            raw_offset
            + raw_size
        )

        if len(output_data) < required_size:
            output_data.extend(
                b"\x00"
                * (
                    required_size
                    - len(output_data)
                )
            )

        # Write actual import-section bytes
        output_data[
            raw_offset:
            raw_offset + virtual_size
        ] = section_data

        # Find room for new section header (40 bytes)
        last_section = self.pe.sections[-1]
        new_section_header_offset = (
            last_section.get_file_offset()
            + 40
        )

        # Safety check to ensure new section header fits within the PE headers
        if (
            new_section_header_offset + 40
            > self.pe.OPTIONAL_HEADER.SizeOfHeaders
        ):
            raise ReconstructionError(
                "PE headers do not contain enough space "
                "for another section header"
            )

        # Write new section header
        padded_name = section_name.ljust(
            8,
            b"\x00",
        )

        # Define section characteristics
        characteristics = (
            0x00000040  # IMAGE_SCN_CNT_INITIALIZED_DATA
            | 0x40000000  # IMAGE_SCN_MEM_READ
            | 0x80000000  # IMAGE_SCN_MEM_WRITE
        )

        struct.pack_into(
            "<8sIIIIIIHHI",
            output_data,
            new_section_header_offset,
            padded_name,
            virtual_size,
            section_rva,
            raw_size,
            raw_offset,
            0,
            0,
            0,
            0,
            characteristics,
        )

        # Update the number of sections in the PE header via pefile
        number_of_sections_offset = (
            self.pe.FILE_HEADER
            .get_field_absolute_offset(
                "NumberOfSections"
            )
        )

        new_section_count = (
            self.pe.FILE_HEADER.NumberOfSections
            + 1
        )

        struct.pack_into(
            "<H",
            output_data,
            number_of_sections_offset,
            new_section_count,
        )

        # Update the SizeOfImage in the PE header
        # New image now ends after .scy
        new_size_of_image = self._align(
            section_rva + virtual_size,
            section_alignment,
        )

        size_of_image_offset = (
            self.pe.OPTIONAL_HEADER
            .get_field_absolute_offset(
                "SizeOfImage"
            )
        )

        struct.pack_into(
            "<I",
            output_data,
            size_of_image_offset,
            new_size_of_image,
        )

        return ReconstructedSection(
            name=section_name.decode(
                errors="replace"
            ),
            virtual_address=section_rva,
            virtual_size=virtual_size,
            raw_offset=raw_offset,
            raw_size=raw_size,
        )

    def reconstruct(
        self,
        output_path: Path | str,
        oep_rva: int,
        import_modules: tuple[ImportModule, ...] | None = None,
    ) -> ReconstructionResult:

        '''
        mapped memory dump
                ↓
        rebuild existing disk sections
                ↓
        patch OEP
                ↓
        patch existing section headers
                ↓
        determine next section RVA
                ↓
        calculate_layout()
                ↓
        build_import_section()
                ↓
        append .scy
                ↓
        add IMAGE_SECTION_HEADER
                ↓
        NumberOfSections += 1
                ↓
        update SizeOfImage
                ↓
        update Import Directory
                ↓
        write PE
                ↓
        pefile validation
        '''

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

        if import_modules:
            import_section_rva = (
                self._get_next_section_rva(
                    section_alignment
                )
            )

            import_layout = calculate_layout(
                import_modules,
                section_rva=import_section_rva,
                pointer_size=8,
            )

            import_section_data = (
                build_import_section(
                    import_layout,
                    pointer_size=8,
                )
            )

            import_section = self.add_import_section(
                output_data=output_data,
                section_data=import_section_data,
                section_rva=import_section_rva,
                file_alignment=file_alignment,
                section_alignment=section_alignment,
            )

            self.update_import_directory(
                output_data=output_data,
                import_rva=(
                    import_layout.descriptor_rva
                ),
                import_size=(
                    import_layout.descriptor_size
                ),
            )

            reconstructed_sections.append(
                import_section
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