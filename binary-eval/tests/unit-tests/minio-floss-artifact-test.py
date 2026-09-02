'''
minio_artifacts.py runner test for floss artifact

With floss.json already extracted and available in 
REMnux VM, minio-artifacts.py runner uploads floss 
JSON file to Minio on Debian datapool VM
'''

from pathlib import PurePosixPath

from runners.vmware import VMwareRunner
from runners.minio_artifacts import MinioArtifactRunner


SHA256 = (
    "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59"
)


remnux_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\REMnux Linux\REMnux Linux\REMnux Linux.vmx",
    guest_username="misha.kurtz",
    password_env_var="REMNUX_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)


artifact_runner = MinioArtifactRunner(remnux_vm)


floss_json_path = PurePosixPath(
    f"/home/misha.kurtz/binary-eval/work/"
    f"B001/original/{SHA256}/static/floss.json"
)


artifact_runner.upload(
    guest_artifact_path=floss_json_path,
    sample_id="B001",
    sample_variant="original",
    sha256=SHA256,
    artifact_name="floss.json",
)


print("floss.json uploaded successfully.")