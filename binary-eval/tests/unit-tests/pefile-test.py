'''
pefile.py runner test

With sample.bin already in binary-eval directory
pefile.py takes the downloaded malware sample, 
extracts PE metadata, and saves to a JSON file
'''

from pathlib import PurePosixPath

from runners.vmware import VMwareRunner
from runners.pefile import PEFileRunner

# SHA-256 hash of the malware sample
SHA256 = (
    "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59"
)

# REMnux VM configuration
remnux_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\REMnux Linux\REMnux Linux\REMnux Linux.vmx",
    guest_username="misha.kurtz",
    password_env_var="REMNUX_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

# pefile runner instance
pefile_runner = PEFileRunner(remnux_vm)

# malware sample path in REMnux VM
sample_path = PurePosixPath(
    f"/home/misha.kurtz/binary-eval/work/"
    f"B001/original/{SHA256}/sample.bin"
)

# output path for PE metadata JSON file in REMnux VM
output_path = PurePosixPath(
    f"/home/misha.kurtz/binary-eval/work/"
    f"B001/original/{SHA256}/static/pe.json"
)

# run the pefile runner to extract PE metadata
pefile_runner.analyze(
    guest_sample_path=sample_path,
    guest_output_path=output_path,
)


print("PE metadata extraction completed.")
print(f"Output: {output_path}")