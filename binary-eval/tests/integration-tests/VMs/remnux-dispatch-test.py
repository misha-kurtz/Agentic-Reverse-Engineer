'''
remnux_dispatch.py runner test

Debian generates presigned URL for malware sample via MinIO
Presigned URL transferred to physical device via textfile
REMnux downloads malware sample from presigned URL
'''

from pathlib import Path, PurePosixPath

from runners.vmware import VMwareRunner
from runners.minio_dispatch import MinioDispatchRunner
from runners.remnux_dispatch import RemnuxDispatchRunner

# SHA-256 hash of the malware sample
SHA256 = (
    "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59"
)

# Debian Datapool VM configuration
datapool = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server.vmx",
    guest_username="kurtz",
    password_env_var="DATAPOOL_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

# REMnux VM configuration
remnux = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\REMnux Linux\REMnux Linux\REMnux Linux.vmx",
    guest_username="misha.kurtz",
    password_env_var="REMNUX_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

# datapool.start()
# remnux.start()

dispatch = MinioDispatchRunner(datapool)
remnux_dispatch = RemnuxDispatchRunner(remnux)

url = dispatch.generate_presigned_url(
    sample_id="B001",
    sha256=SHA256,
    host_temp_path=Path(
        r"C:\Users\MK\AppData\Local\Temp\presigned_url.txt"
    ),
)

print("Presigned URL generated.")

remnux_dispatch.download_and_verify(
    presigned_url=url,
    expected_sha256=SHA256,
    guest_sample_path=PurePosixPath(
        f"/home/misha.kurtz/binary-eval/B001/{SHA256}/sample.bin"
    ),
)

print("REMnux download and SHA-256 verification succeeded.")

# datapool.stop()
# remnux.stop()