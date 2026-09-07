from runners.vmware import VMwareRunner
from runners.ubuntu import UbuntuRunner
from runners.inetsim import INetSimRunner


ubuntu_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway.vmx",
    guest_username="kurtz",
    password_env_var="UBUNTU_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

ubuntu_was_running = ubuntu_vm.is_running()

try:
    ubuntu_vm.start()
    ubuntu_vm.wait_for_guest(shell="bash")

    ubuntu_runner = UbuntuRunner(ubuntu_vm)
    inetsim_runner = INetSimRunner(ubuntu_vm)

    ubuntu_runner.clean_dynamic_workspace(
        sample_id="B001",
        sample_variant="encrypted",
        sha256="test-sha256",
    )

    dynamic_dir = ubuntu_runner.prepare_dynamic_workspace(
        sample_id="B001",
        sample_variant="encrypted",
        sha256="test-sha256",
    )

    inetsim_runner.start(dynamic_dir)

    if not inetsim_runner.is_running():
        raise RuntimeError("INetSim failed to start")

    print("INetSim is running")

    inetsim_runner.stop()

    if inetsim_runner.is_running():
        raise RuntimeError("INetSim failed to stop")

    print("INetSim stopped successfully")

finally:
    try:
        inetsim_runner.stop()
    except Exception:
        pass

    if not ubuntu_was_running:
        try:
            ubuntu_vm.stop()
        except RuntimeError:
            pass