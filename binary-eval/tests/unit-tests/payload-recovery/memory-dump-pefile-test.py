from pathlib import Path

import pefile


dump_path = Path(
    r"C:\Users\misha.kurtz\Agentic-Reverse-Engineer\binary-eval\dumps\bind_shell_packed_memory.bin"
)

pe = pefile.PE(
    str(dump_path),
    fast_load=False,
)

print(f"ImageBase:            0x{pe.OPTIONAL_HEADER.ImageBase:X}")
print(f"AddressOfEntryPoint:  0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
print(f"SizeOfImage:          0x{pe.OPTIONAL_HEADER.SizeOfImage:X}")

print()
print("Sections:")

for section in pe.sections:
    name = section.Name.rstrip(b"\x00").decode(
        errors="replace"
    )

    print(
        f"{name:8} "
        f"VA=0x{section.VirtualAddress:X} "
        f"VS=0x{section.Misc_VirtualSize:X} "
        f"RAW=0x{section.PointerToRawData:X} "
        f"RS=0x{section.SizeOfRawData:X}"
    )