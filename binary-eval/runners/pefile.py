from pathlib import PurePosixPath

from detection.signatures import KNOWN_UPX_MARKERS
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

        upx_markers = list(KNOWN_UPX_MARKERS)

        command = f"""
mkdir -p "{output_dir}" &&
python3 - 2>&1 <<'PY'
import json
import pefile

sample_path = "{sample_path}"
output_path = "{output_path}"

known_upx_markers = {upx_markers!r}

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
    "imports": [],
    "packer_markers": []
}}

for section in pe.sections:
    data["sections"].append({{
        "name": section.Name.decode(errors="replace").rstrip("\\x00"),
        "virtual_address": section.VirtualAddress,
        "virtual_size": section.Misc_VirtualSize,
        "raw_size": section.SizeOfRawData,
        "characteristics": section.Characteristics,
        "entropy": section.get_entropy()
    }})

entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
entry_point_section = None

for section in pe.sections:
    start = section.VirtualAddress
    end = start + max(
        section.Misc_VirtualSize,
        section.SizeOfRawData,
    )

    if start <= entry_point_rva < end:
        entry_point_section = (
            section.Name.decode(errors="replace")
            .rstrip("\\x00")
        )
        break

data["entry_point_section"] = entry_point_section

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

with open(sample_path, "rb") as f:
    raw_data = f.read()

for marker in known_upx_markers:
    if marker in raw_data:
        data["packer_markers"].append(
            marker.decode("ascii", errors="replace")
        )

with open(output_path, "w") as f:
    json.dump(data, f, indent=2)

pe.close()
PY
"""

        self.remnux_vm.run_bash(command)