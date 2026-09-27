# Test reconstruction of PE from dumped memory image before wiring into runtime_unpack.py
from pathlib import Path

from runners.reconstruction import PEReconstructor


memory_dump = Path(
    r"dumps\bind_shell_packed_memory.bin"
)

output = Path(
    r"dumps\bind_shell_reconstructed.exe"
)

reconstructor = PEReconstructor(
    memory_dump
)

result = reconstructor.reconstruct(
    output_path=output,
    oep_rva=0x17E0,
)

print()
print(f"Input:            {result.input_path}")
print(f"Output:           {result.output_path}")
print(f"Old OEP:          0x{result.original_oep_rva:X}")
print(f"Recovered OEP:    0x{result.recovered_oep_rva:X}")
print(f"File alignment:   0x{result.file_alignment:X}")
print(f"Section alignment:0x{result.section_alignment:X}")
print(f"Output size:      0x{result.output_size:X}")

print()
print("Sections:")

for section in result.sections:
    print(
        f"{section.name:8} "
        f"RVA=0x{section.virtual_address:X} "
        f"VS=0x{section.virtual_size:X} "
        f"RAW=0x{section.raw_offset:X} "
        f"RS=0x{section.raw_size:X}"
    )