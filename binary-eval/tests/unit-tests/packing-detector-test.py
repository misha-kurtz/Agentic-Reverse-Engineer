import json
from pathlib import Path

from detection.packing import detect_packing


pe_path = Path(r"D:\Virtual Machines\shared\pe_encrypted.json")

with pe_path.open("r") as f:
    pe_data = json.load(f)

assessment = detect_packing(pe_data)

print("Detected:", assessment.detected)
print("Confidence:", assessment.confidence)
print("Family:", assessment.family)
print("Indicators:")

for indicator in assessment.indicators:
    print(f"  - {indicator}")