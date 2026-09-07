from runners.vmware import VMwareRunner
from runners.ubuntu import UbuntuRunner


ubuntu_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway.vmx",
    guest_username="kurtz",
    password_env_var="UBUNTU_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

ubuntu_was_running = ubuntu_vm.is_running()

try:
    ubuntu_vm.start()
    ubuntu_vm.wait_for_guest()

    ubuntu_runner = UbuntuRunner(
        ubuntu_vm=ubuntu_vm,
    )

    ubuntu_runner.clean_dynamic_workspace(
        sample_id="B001",
        sample_variant="packed",
        sha256="test-sha256",
    )

    guest_dynamic_dir = (
        ubuntu_runner.prepare_dynamic_workspace(
            sample_id="B001",
            sample_variant="packed",
            sha256="test-sha256",
        )
    )

    print("Ubuntu VM execution completed")
    print(f"dynamic_dir: {guest_dynamic_dir}")

finally:
    if not ubuntu_was_running:
        try:
            ubuntu_vm.stop()
        except RuntimeError:
            pass