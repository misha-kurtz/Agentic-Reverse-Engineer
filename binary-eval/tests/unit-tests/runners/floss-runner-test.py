'''
floss.py runner test for FLOSS string extraction

With sample.bin  already downloaded to REMnux VM, 
floss.py runner starts FLOSS string extraction for
the malware sample and saves to JSON file on REMnux VM
'''

from pathlib import PurePosixPath

from runners.vmware import VMwareRunner
from runners.floss import FLOSSRunner


SHA256 = (
    "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59"
)


remnux_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\REMnux Linux\REMnux Linux\REMnux Linux.vmx",
    guest_username="misha.kurtz",
    password_env_var="REMNUX_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)


floss_runner = FLOSSRunner(remnux_vm)


sample_path = PurePosixPath(
    f"/home/misha.kurtz/binary-eval/work/"
    f"B001/original/{SHA256}/sample.bin"
)

output_path = PurePosixPath(
    f"/home/misha.kurtz/binary-eval/work/"
    f"B001/original/{SHA256}/static/floss.json"
)


floss_runner.analyze(
    guest_sample_path=sample_path,
    guest_output_path=output_path,
)


print("FLOSS analysis completed.")
print(f"Output: {output_path}")