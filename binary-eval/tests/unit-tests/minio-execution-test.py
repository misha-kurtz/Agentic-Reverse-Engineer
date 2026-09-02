# MinIO access from Datapool test
from pathlib import Path

from runners.vmware import VMwareRunner
from runners.minio_dispatch import MinioDispatchRunner


datapool = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server.vmx",
    guest_username="kurtz",
    password_env_var="DATAPOOL_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

datapool.start()

datapool.run_bash(
    """
    {
        echo "USER=$(whoami)"
        echo "HOME=$HOME"
        echo "PATH=$PATH"
        echo "MC=$(command -v mc)"
        mc --version
        mc alias list
    } > /tmp/mc-test.txt 2>&1
    """
)

datapool.copy_from_guest(
    "/tmp/mc-test.txt",
    r"C:\Users\MK\AppData\Local\Temp\mc-test.txt",
)

print("Datapool guest execution test completed.")


datapool.stop()