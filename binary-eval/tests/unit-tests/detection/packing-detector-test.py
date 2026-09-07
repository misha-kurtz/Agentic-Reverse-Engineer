import json
from pathlib import Path

from detection.packing import detect_packing


pe_path = Path(r"D:\Virtual Machines\shared\test\encrypted\pe.json")
capa_path = Path(r"D:\Virtual Machines\shared\test\encrypted\capa.json")
ghidra_metrics_path = Path(r"D:\Virtual Machines\shared\test\encrypted\metrics.json")


with pe_path.open("r") as f:
    pe_data = json.load(f)

with capa_path.open("r") as f:
    capa_data = json.load(f)

with ghidra_metrics_path.open("r") as f:
    ghidra_metrics = json.load(f)


assessment = detect_packing(
    pe_data=pe_data,
    capa_data=capa_data,
    ghidra_metrics=ghidra_metrics,
)

print("Detected:", assessment.detected)
print("Confidence:", assessment.confidence)
print("Family:", assessment.family)

print("Indicators:")

for indicator in assessment.indicators:
    print(f"  - {indicator}")