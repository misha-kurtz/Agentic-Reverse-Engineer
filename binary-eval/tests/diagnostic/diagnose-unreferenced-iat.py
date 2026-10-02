from pathlib import Path
import struct

import pefile

from capstone import (
    Cs,
    CS_ARCH_X86,
    CS_MODE_64,
)

from capstone.x86_const import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_REG_RIP,
)


RECONSTRUCTED = Path(r"C:\analysis\bind_shell_reconstructed.exe")

# Optional comparison against the original clean,
# pre-UPX bind shell.
ORIGINAL = Path(r"C:\analysis\bind.exe")


TARGETS = {
    0x16008: "KERNEL32.dll!WriteConsoleW",
    0x16010: "KERNEL32.dll!CreateFileW",
    0x16018: "ntdll.dll!RtlReAllocateHeap",
    0x16020: "ntdll.dll!RtlSizeHeap",
    0x16220: "KERNEL32.dll!SetEnvironmentVariableW",
}


def scan_pe(
    path: Path,
    target_rvas: dict[int, str],
) -> None:

    print()
    print("=" * 80)
    print(f"Scanning: {path}")
    print("=" * 80)

    pe = pefile.PE(
        str(path),
        fast_load=False,
    )

    data = path.read_bytes()

    disassembler = Cs(
        CS_ARCH_X86,
        CS_MODE_64,
    )

    disassembler.detail = True

    image_base = (
        pe.OPTIONAL_HEADER.ImageBase
    )

    hits: dict[int, list[str]] = {
        rva: []
        for rva in target_rvas
    }

    for section in pe.sections:
        if not (
            section.Characteristics
            & 0x20000000
        ):
            continue

        section_name = (
            section.Name
            .rstrip(b"\x00")
            .decode(errors="replace")
        )

        section_rva = (
            section.VirtualAddress
        )

        raw_offset = (
            section.PointerToRawData
        )

        raw_size = (
            section.SizeOfRawData
        )

        if raw_size == 0:
            continue

        section_data = data[
            raw_offset:
            raw_offset + raw_size
        ]

        print()
        print(
            f"[debug] Scanning executable section "
            f"{section_name} "
            f"RVA 0x{section_rva:X}"
        )

        for instruction in (
            disassembler.disasm(
                section_data,
                section_rva,
            )
        ):
            for operand in instruction.operands:

                #
                # RIP-relative memory reference.
                #
                if (
                    operand.type == X86_OP_MEM
                    and operand.mem.base == X86_REG_RIP
                ):
                    target_rva = (
                        instruction.address
                        + instruction.size
                        + operand.mem.disp
                    )

                    if target_rva in target_rvas:
                        hits[target_rva].append(
                            (
                                f"RIP-relative: "
                                f"RVA 0x{instruction.address:X}: "
                                f"{instruction.mnemonic} "
                                f"{instruction.op_str}"
                            )
                        )

                #
                # Immediate RVA.
                #
                elif operand.type == X86_OP_IMM:
                    immediate = operand.imm

                    if immediate in target_rvas:
                        hits[immediate].append(
                            (
                                f"Immediate RVA: "
                                f"RVA 0x{instruction.address:X}: "
                                f"{instruction.mnemonic} "
                                f"{instruction.op_str}"
                            )
                        )

                    #
                    # Absolute VA form.
                    #
                    absolute_rva = (
                        immediate
                        - image_base
                    )

                    if absolute_rva in target_rvas:
                        hits[absolute_rva].append(
                            (
                                f"Immediate VA: "
                                f"RVA 0x{instruction.address:X}: "
                                f"{instruction.mnemonic} "
                                f"{instruction.op_str}"
                            )
                        )

    #
    # Raw byte search for the RVA encoded directly.
    #
    for target_rva, symbol in target_rvas.items():
        encoded_rva = struct.pack(
            "<I",
            target_rva,
        )

        start = 0

        while True:
            offset = data.find(
                encoded_rva,
                start,
            )

            if offset == -1:
                break

            hits[target_rva].append(
                f"Raw 32-bit RVA bytes at file offset 0x{offset:X}"
            )

            start = offset + 1

        absolute_va = (
            image_base
            + target_rva
        )

        encoded_va = struct.pack(
            "<Q",
            absolute_va,
        )

        start = 0

        while True:
            offset = data.find(
                encoded_va,
                start,
            )

            if offset == -1:
                break

            hits[target_rva].append(
                f"Raw 64-bit VA bytes at file offset 0x{offset:X}"
            )

            start = offset + 1

    print()
    print("[debug] Unreferenced-IAT diagnostic results:")

    for target_rva, symbol in target_rvas.items():
        print()
        print(
            f"0x{target_rva:X} "
            f"{symbol}"
        )

        references = hits[
            target_rva
        ]

        if not references:
            print(
                "  No references found"
            )

            continue

        for reference in references:
            print(
                f"  {reference}"
            )

    pe.close()


scan_pe(
    RECONSTRUCTED,
    TARGETS,
)


if ORIGINAL.exists():
    scan_pe(
        ORIGINAL,
        TARGETS,
    )
else:
    print()
    print(
        "[debug] Original clean bind shell "
        "not found; skipping comparison."
    )

print("[debug] diagnostic script started")

print(f"[debug] reconstructed path: {RECONSTRUCTED}")
print(f"[debug] exists: {RECONSTRUCTED.exists()}")

scan_pe(
    RECONSTRUCTED,
    TARGETS,
)

print("[debug] diagnostic script finished")