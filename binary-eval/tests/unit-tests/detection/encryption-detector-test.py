import json
from pathlib import Path

from detection.encryption import detect_encryption


# --------------------------------------------------
# Change these paths for the sample being tested.
# --------------------------------------------------

pe_path = Path(r"D:\Virtual Machines\shared\test\encrypted\pe.json")
capa_path = Path(r"D:\Virtual Machines\shared\test\encrypted\capa.json")
ghidra_metrics_path = Path(r"D:\Virtual Machines\shared\test\encrypted\metrics.json")



# --------------------------------------------------
# Load static artifacts.
# --------------------------------------------------

with pe_path.open("r") as f:
    pe_data = json.load(f)

with capa_path.open("r") as f:
    capa_data = json.load(f)

with ghidra_metrics_path.open("r") as f:
    ghidra_metrics = json.load(f)


# --------------------------------------------------
# Run encryption detector.
# --------------------------------------------------

assessment = detect_encryption(
    pe_data=pe_data,
    capa_data=capa_data,
    ghidra_metrics=ghidra_metrics,
)


# --------------------------------------------------
# Print assessment.
# --------------------------------------------------

print("Suspected:", assessment.suspected)
print("Confidence:", assessment.confidence)
print("Family:", assessment.family)

print("Indicators:")

for indicator in assessment.indicators:
    print(f"  - {indicator}")