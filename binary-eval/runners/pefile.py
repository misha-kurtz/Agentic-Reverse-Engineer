import json
from pathlib import PurePosixPath

from runners.vmware import VMwareRunner


class PEFileRunner:
    def __init__(self, remnux_vm: VMwareRunner):
        self.remnux_vm = remnux_vm

    def analyze(
        self,
        guest_sample_path: PurePosixPath,
        guest_output_path: PurePosixPath,
    ) -> None:

        sample_path = str(guest_sample_path)
        output_path = str(guest_output_path)
        output_dir = str(guest_output_path.parent)

        command = f"""
mkdir -p "{output_dir}" &&
python3 - <<'PY'
import json
import pefile

sample_path = "{sample_path}"
output_path = "{output_path}"

pe = pefile.PE(sample_path)

data = {{
    "machine": pe.FILE_HEADER.Machine,
    "number_of_sections": pe.FILE_HEADER.NumberOfSections,
    "timestamp": pe.FILE_HEADER.TimeDateStamp,
    "characteristics": pe.FILE_HEADER.Characteristics,

    "image_base": pe.OPTIONAL_HEADER.ImageBase,
    "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
    "section_alignment": pe.OPTIONAL_HEADER.SectionAlignment,
    "file_alignment": pe.OPTIONAL_HEADER.FileAlignment,
    "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,

    "sections": [],
    "imports": []
}}

for section in pe.sections:
    data["sections"].append({{
        "name": section.Name.decode(errors="replace").rstrip("\\x00"),
        "virtual_address": section.VirtualAddress,
        "virtual_size": section.Misc_VirtualSize,
        "raw_size": section.SizeOfRawData,
        "entropy": section.get_entropy()
    }})

if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = {{
            "dll": entry.dll.decode(errors="replace"),
            "imports": []
        }}

        for imp in entry.imports:
            dll["imports"].append({{
                "name": (
                    imp.name.decode(errors="replace")
                    if imp.name
                    else None
                ),
                "ordinal": imp.ordinal,
                "address": imp.address
            }})

        data["imports"].append(dll)

with open(output_path, "w") as f:
    json.dump(data, f, indent=2)

pe.close()
PY
"""

        self.remnux_vm.run_bash(command)