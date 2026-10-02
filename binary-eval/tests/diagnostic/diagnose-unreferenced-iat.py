from pathlib import Path

import pefile

from capstone import (
    Cs,
    CS_ARCH_X86,
    CS_MODE_64,
)


RECONSTRUCTED = Path(
    r"C:\analysis\bind_shell_reconstructed.exe"
)

ORIGINAL = Path(
    r"C:\analysis\bind.exe"
)


TARGET_RVAS = {
    0x1246E: "SetEnvironmentVariableW",
    0x13D46: "CreateFileW",
    0x13DB4: "WriteConsoleW",
    0x13E09: "CreateFileW",
    0x13E2B: "WriteConsoleW",
}


def inspect_target_rvas(
    path: Path,
    target_rvas: dict[int, str],
) -> None:

    print()
    print("=" * 80)
    print(f"Scanning: {path}")
    print("=" * 80)

    if not path.exists():
        print("[error] File does not exist")
        return

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

    for target_rva, symbol in target_rvas.items():

        print()
        print(
            f"=== RVA 0x{target_rva:X} "
            f"({symbol}) ==="
        )

        containing_section = None

        for section in pe.sections:
            section_start = (
                section.VirtualAddress
            )

            section_end = (
                section_start
                + max(
                    section.Misc_VirtualSize,
                    section.SizeOfRawData,
                )
            )

            if (
                section_start
                <= target_rva
                < section_end
            ):
                containing_section = section
                break

        if containing_section is None:
            print(
                "RVA is not contained "
                "in any section"
            )
            continue

        section_name = (
            containing_section.Name
            .rstrip(b"\x00")
            .decode(errors="replace")
        )

        file_offset = (
            containing_section.PointerToRawData
            + (
                target_rva
                - containing_section.VirtualAddress
            )
        )

        print(
            f"Section: {section_name}"
        )

        print(
            f"File offset: 0x{file_offset:X}"
        )

        #
        # Start 16 bytes before the target so we can
        # see some surrounding instructions.
        #
        context_start_offset = max(
            file_offset - 16,
            0,
        )

        context_start_rva = (
            target_rva
            - (
                file_offset
                - context_start_offset
            )
        )

        context_end_offset = min(
            file_offset + 32,
            len(data),
        )

        code = data[
            context_start_offset:
            context_end_offset
        ]

        instructions = list(
            disassembler.disasm(
                code,
                context_start_rva,
            )
        )

        if not instructions:
            print(
                "No instructions decoded"
            )
            continue

        found_exact_target = False

        for instruction in instructions:

            marker = ""

            if (
                instruction.address
                == target_rva
            ):
                marker = "  <-- TARGET"
                found_exact_target = True

            print(
                f"0x{instruction.address:05X}: "
                f"{instruction.mnemonic:<8} "
                f"{instruction.op_str}"
                f"{marker}"
            )

        if not found_exact_target:
            print()
            print(
                "[warning] Capstone did not "
                "decode an instruction beginning "
                "exactly at the target RVA."
            )

    pe.close()


print(
    "[debug] diagnostic script started"
)

inspect_target_rvas(
    RECONSTRUCTED,
    TARGET_RVAS,
)


if ORIGINAL.exists():
    inspect_target_rvas(
        ORIGINAL,
        TARGET_RVAS,
    )
else:
    print()
    print(
        "[debug] Original clean bind shell "
        "not found; skipping comparison."
    )


print(
    "[debug] diagnostic script finished"
)