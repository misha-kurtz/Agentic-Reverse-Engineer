from pathlib import PurePosixPath

from runners.vmware import VMwareRunner
from runners.ghidra import GhidraRunner


SHA256 = (
    "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59"
)


remnux_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\REMnux Linux\REMnux Linux\REMnux Linux.vmx",
    guest_username="misha.kurtz",
    password_env_var="REMNUX_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)


ghidra_runner = GhidraRunner(
    remnux_vm=remnux_vm,

    # Replace this with the actual path returned by find
    analyze_headless_path=PurePosixPath(
        "/opt/ghidra/support/analyzeHeadless"
    ),

    script_path=PurePosixPath(
        "/home/misha.kurtz/binary-eval/ghidra-scripts"
    ),
)


sample_path = PurePosixPath(
    f"/home/misha.kurtz/binary-eval/work/"
    f"B001/original/{SHA256}/sample.bin"
)

output_dir = PurePosixPath(
    f"/home/misha.kurtz/binary-eval/work/"
    f"B001/original/{SHA256}/static/ghidra"
)


ghidra_runner.analyze(
    guest_sample_path=sample_path,
    guest_output_dir=output_dir,
)


print("Ghidra headless test completed.")
print(f"Output directory: {output_dir}")