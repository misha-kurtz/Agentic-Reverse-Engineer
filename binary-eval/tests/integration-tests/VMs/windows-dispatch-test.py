from pathlib import Path, PureWindowsPath

from runners.minio_dispatch import MinioDispatchRunner
from runners.windows_dispatch import WindowsDispatchRunner
from runners.vmware import VMwareRunner

SHA256 = (
    "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59"
)

windows_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Windows 11 x64\Windows 11 x64\Windows 11 x64.vmx",
    guest_username=r".\misha.kurtz",
    password_env_var="WINDOWS_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)


datapool_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server.vmx",
    guest_username="kurtz",
    password_env_var="DATAPOOL_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

windows_vm.start()
windows_vm.wait_for_guest(shell="windows")

#datapool_vm.start()
#datapool_vm.wait_for_guest(shell="bash")

windows_dispatch = WindowsDispatchRunner(
    windows_vm
)

minio_dispatch = MinioDispatchRunner(
    datapool_vm
)

presigned_url = (
    minio_dispatch.generate_presigned_url(
        sample_id="B001",
        sha256=SHA256,
        sample_variant="original",
        host_temp_path=Path(
            r"C:\Users\MK\AppData\Local\Temp\presigned_url.txt"
        ),
    )
)

windows_dispatch.clean_sample_workspace(
    sample_id="B001",
    sample_variant="original",
    sha256=SHA256,
)

guest_sample_path = PureWindowsPath(
    rf"C:\binary-eval\work\B001"
    rf"\original\{SHA256}\sample.exe"
)


windows_dispatch.download_and_verify(
    presigned_url=presigned_url,
    expected_sha256=SHA256,
    guest_sample_path=guest_sample_path,
)

print("Windows sample download and SHA256 verification completed")

windows_vm.stop()
#datapool_vm.stop()