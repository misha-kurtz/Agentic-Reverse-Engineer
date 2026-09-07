from pathlib import Path, PureWindowsPath

from controller.controller import AnalysisController

from runners.vmware import VMwareRunner
from runners.minio_dispatch import MinioDispatchRunner   
from runners.windows_dispatch import WindowsDispatchRunner
from runners.ubuntu import UbuntuRunner

# Change sample_variant to match SHA256 hash of sample
SHA256 = (
    "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59"
)
SAMPLE_ID = "B001"
SAMPLE_VARIANT = "original"



'''
SHA256 = (
    "c1d38e72ae55dc9232c962df041ef5371bf53cce1696867360ebcacd2d914109"
)
SHA256 = (
    "7141ef42cb8c213e2ee02cb2ef18e5bf8e862282ab236d39f4115199c16bf402"
)
'''


datapool_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server.vmx",
    guest_username="kurtz",
    password_env_var="DATAPOOL_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)


windows_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Windows 11 x64\Windows 11 x64\Windows 11 x64.vmx",
    guest_username="misha.kurtz",
    password_env_var="WINDOWS_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

ubuntu_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway.vmx",
    guest_username="kurtz",
    password_env_var="UBUNTU_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

datapool_was_running = datapool_vm.is_running()
windows_was_running = windows_vm.is_running()
ubuntu_was_running = ubuntu_vm.is_running()


try:
    # --------------------------------------------------
    # Start infrastructure
    # --------------------------------------------------

    datapool_vm.start()
    windows_vm.start()
    ubuntu_vm.start()

    datapool_vm.wait_for_guest(shell="bash")
    windows_vm.wait_for_guest(shell="windows")
    ubuntu_vm.wait_for_guest(shell="bash")

    # --------------------------------------------------
    # Instantiate runners
    # --------------------------------------------------

    minio_dispatch = MinioDispatchRunner(datapool_vm)
    windows_dispatch = WindowsDispatchRunner(windows_vm)
    ubuntu_runner = UbuntuRunner(ubuntu_vm)

    minio_dispatch.wait_for_minio()

    # --------------------------------------------------
    # Prepare Ubuntu dynamic workspace
    # --------------------------------------------------

    ubuntu_runner.clean_dynamic_workspace(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    ubuntu_dynamic_dir = ubuntu_runner.prepare_dynamic_workspace(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    # --------------------------------------------------
    # Prepare Windows workspace
    # --------------------------------------------------

    windows_dispatch.clean_sample_workspace(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    windows_sample_path = PureWindowsPath(
        rf"C:\binary-eval\work\{SAMPLE_ID}"
        rf"\{SAMPLE_VARIANT}\{SHA256}\sample.exe"
    )

    # --------------------------------------------------
    # Generate fresh dynamic presigned URL
    # --------------------------------------------------

    dynamic_presigned_url = minio_dispatch.generate_presigned_url(
        sample_id=SAMPLE_ID,
        sha256=SHA256,
        sample_variant=SAMPLE_VARIANT,
        host_temp_path=Path(
            r"C:\Users\MK\AppData\Local\Temp\dynamic_presigned_url.txt"
        ),
    )

    # --------------------------------------------------
    # Download sample to Windows and verify SHA256
    # --------------------------------------------------

    windows_dispatch.download_and_verify(
        presigned_url=dynamic_presigned_url,
        expected_sha256=SHA256,
        guest_sample_path=windows_sample_path,
    )

    print("Dynamic infrastructure integration test completed")
    print(f"Ubuntu dynamic directory: {ubuntu_dynamic_dir}")
    print(f"Windows sample path: {windows_sample_path}")


finally:
    if not ubuntu_was_running:
        try:
            ubuntu_vm.stop()
        except RuntimeError:
            pass

    if not windows_was_running:
        try:
            windows_vm.stop()
        except RuntimeError:
            pass

    if not datapool_was_running:
        try:
            datapool_vm.stop()
        except RuntimeError:
            pass