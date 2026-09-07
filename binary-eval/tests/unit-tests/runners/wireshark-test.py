import time

from runners.vmware import VMwareRunner
from runners.ubuntu import UbuntuRunner
from runners.wireshark import WiresharkRunner


ubuntu_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway.vmx",
    guest_username="kurtz",
    password_env_var="UBUNTU_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

ubuntu_was_running = ubuntu_vm.is_running()
dynamic_dir = None

try:
    ubuntu_vm.start()
    ubuntu_vm.wait_for_guest(shell="bash")

    ubuntu_runner = UbuntuRunner(ubuntu_vm)
    wireshark_runner = WiresharkRunner(ubuntu_vm, interface="ens33")

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

    pcap_path = wireshark_runner.start(dynamic_dir)

    if not wireshark_runner.is_running(dynamic_dir):
        raise RuntimeError("Wireshark/tshark capture failed to start")

    print("Wireshark/tshark capture is running")
    print(f"pcap_path: {pcap_path}")

    time.sleep(10)

    wireshark_runner.stop(dynamic_dir)

    if wireshark_runner.is_running(dynamic_dir):
        raise RuntimeError("Wireshark/tshark capture failed to stop")

    print("Wireshark/tshark capture stopped successfully")

    ubuntu_vm.run_bash(f'test -s "{pcap_path}"')

    print("PCAP file exists and is not empty")

finally:
    if dynamic_dir is not None:
        try:
            wireshark_runner.stop(dynamic_dir)
        except Exception:
            pass

    if not ubuntu_was_running:
        try:
            ubuntu_vm.stop()
        except RuntimeError:
            pass