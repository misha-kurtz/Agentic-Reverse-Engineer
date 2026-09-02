# Debian Datapool VM control test
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
    "hostname > /tmp/datapool-test.txt && "
    "whoami >> /tmp/datapool-test.txt && "
    "pwd >> /tmp/datapool-test.txt"
)

datapool.copy_from_guest(
    "/tmp/datapool-test.txt",
    r"C:\Users\MK\AppData\Local\Temp\datapool-test.txt",
)

print("Datapool guest execution test completed.")



datapool.stop()