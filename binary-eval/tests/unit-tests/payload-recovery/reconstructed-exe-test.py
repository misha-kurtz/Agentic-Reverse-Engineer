import pefile

pe = pefile.PE(
    r"dumps\bind_shell_reconstructed.exe"
)

print(f"ImageBase:           0x{pe.OPTIONAL_HEADER.ImageBase:X}")
print(f"OEP:                 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
print(f"SizeOfImage:         0x{pe.OPTIONAL_HEADER.SizeOfImage:X}")
print(f"SizeOfHeaders:       0x{pe.OPTIONAL_HEADER.SizeOfHeaders:X}")

print()

for section in pe.sections:
    name = section.Name.rstrip(b"\x00").decode()

    print(
        f"{name:8} "
        f"VA=0x{section.VirtualAddress:X} "
        f"VS=0x{section.Misc_VirtualSize:X} "
        f"RAW=0x{section.PointerToRawData:X} "
        f"RS=0x{section.SizeOfRawData:X}"
    )