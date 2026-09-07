import time

from runners.vmware import VMwareRunner
from runners.ubuntu import UbuntuRunner
from runners.inetsim import INetSimRunner
from runners.wireshark import WiresharkRunner


ubuntu_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway.vmx",
    guest_username="kurtz",
    password_env_var="UBUNTU_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

windows_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Windows 11 x64\Windows 11 x64\Windows 11 x64.vmx",
    guest_username=r".\misha.kurtz",
    password_env_var="WINDOWS_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

ubuntu_was_running = ubuntu_vm.is_running()
windows_was_running = windows_vm.is_running()
dynamic_dir = None
inetsim_runner = None
wireshark_runner = None

try:
    ubuntu_vm.start()
    ubuntu_vm.wait_for_guest(shell="bash")
    windows_vm.start()
    windows_vm.wait_for_guest(shell="windows")

    ubuntu_runner = UbuntuRunner(ubuntu_vm)
    inetsim_runner = INetSimRunner(ubuntu_vm)
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

    inetsim_runner.start(dynamic_dir)

    if not inetsim_runner.is_running():
        raise RuntimeError("INetSim failed to start")

    print("INetSim is running")

    pcap_path = wireshark_runner.start(dynamic_dir)

    if not wireshark_runner.is_running(dynamic_dir):
        raise RuntimeError("tshark failed to start")

    print("tshark capture is running")
    print(f"pcap_path: {pcap_path}")

    time.sleep(2)

    windows_vm.run_powershell('ping.exe -n 4 192.168.67.5')

    windows_vm.run_powershell('curl.exe --max-time 5 http://192.168.67.5/index.html')

    time.sleep(5)

    wireshark_runner.stop(dynamic_dir)
    if wireshark_runner.is_running(dynamic_dir):
        raise RuntimeError("tshark failed to stop")

    print("tshark stopped successfully")

    inetsim_runner.stop()

    if inetsim_runner.is_running():
        raise RuntimeError("INetSim failed to stop")

    print("INetSim stopped successfully")

    ubuntu_vm.run_bash(f'test -s "{pcap_path}"')

    print("PCAP file exists and is not empty")
    print("Dynamic network integration test completed")

finally:
    if wireshark_runner is not None and dynamic_dir is not None:
        try:
            wireshark_runner.stop(dynamic_dir)
        except Exception:
            pass

    if inetsim_runner is not None:
        try:
            inetsim_runner.stop()
        except Exception:
            pass

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

    