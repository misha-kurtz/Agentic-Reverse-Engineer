'''
minio_dispatch.py runner test

Debian generates presigned URL for malware sample via MinIO
Presigned URL transferred to physical device via textfile
'''

from pathlib import Path

from runners.vmware import VMwareRunner
from runners.minio_dispatch import MinioDispatchRunner


SHA256 = (
    "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59"
)

datapool = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server.vmx",
    guest_username="kurtz",
    password_env_var="DATAPOOL_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

#datapool.start()

dispatch = MinioDispatchRunner(datapool)

url = dispatch.generate_presigned_url(
    sample_id="B001",
    sha256=SHA256,
    host_temp_path=Path(
        r"C:\Users\MK\AppData\Local\Temp\presigned_url.txt"
    ),
)

print("Presigned URL generated:")
print(url)

#datapool.stop()