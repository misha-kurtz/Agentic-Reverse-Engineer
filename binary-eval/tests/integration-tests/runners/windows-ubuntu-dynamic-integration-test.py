'''
Milestone: full cross-VM (Windows/Ubuntu) dynamic telemetry

start Windows GUI
start Ubuntu
        ↓
clean Windows sample workspace
prepare Windows + Ubuntu output dirs
        ↓
start INetSim
start tshark
        ↓
start Windows instrumentation
        ↓
generate benign Windows activity
generate HTTP/DNS traffic toward Ubuntu
        ↓
stop/finish collectors
        ↓
collect:
  Noriben
  Regshot
  Sysmon
  PCAP
  INetSim logs
'''


# binary-eval/windows-ubuntu-dynamic-integration-test.py

from pathlib import PureWindowsPath

from runners.vmware import VMwareRunner
from runners.windows_dispatch import WindowsDispatchRunner
from runners.noriben import NoribenRunner
from runners.regshot import RegshotRunner
from runners.sysmon import SysmonRunner
from runners.inetsim import INetSimRunner
from runners.wireshark import WiresharkRunner
from runners.ubuntu import UbuntuRunner


SAMPLE_ID = "B001"
VARIANT = "test"
SHA256 = "test-sha256"

UBUNTU_IP = "192.168.67.5"


# ----------------------------------------------------------------
# VMware runners
# ----------------------------------------------------------------

windows_vm = VMwareRunner(
    vmx_path=PureWindowsPath(
        r"D:\Virtual Machines\Windows 11 x64\Windows 11 x64\Windows 11 x64.vmx"
    ),
    guest_username=r".\misha.kurtz",
    password_env_var="WINDOWS_GUEST_PASSWORD",
    vmrun_path=PureWindowsPath(
        r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"
    ),
)

ubuntu_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway.vmx",
    guest_username="kurtz",
    password_env_var="UBUNTU_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)


# ----------------------------------------------------------------
# Dispatch
# ----------------------------------------------------------------

windows_dispatch = WindowsDispatchRunner(
    windows_vm=windows_vm
)

ubuntu = UbuntuRunner(
    ubuntu_vm=ubuntu_vm
)


# ----------------------------------------------------------------
# Windows instrumentation
# ----------------------------------------------------------------

noriben = NoribenRunner(
    windows_vm=windows_vm,
    python_path=PureWindowsPath(
        r"C:\Users\misha.kurtz\AppData\Local\Microsoft\WindowsApps\python.exe"
    ),
    noriben_path=PureWindowsPath(
        r"C:\Users\misha.kurtz\dynamic_analysis\Noriben\Noriben.py"
    ),
)

regshot = RegshotRunner(
    windows_vm=windows_vm,
    python_path=PureWindowsPath(
        r"C:\Users\misha.kurtz\AppData\Local\Microsoft\WindowsApps\python.exe"
    ),
    regshot_path=PureWindowsPath(
        r"C:\Users\misha.kurtz\dynamic_analysis\Regshot-1.9.0\Regshot-x64-Unicode.exe"
    ),
)

sysmon = SysmonRunner(
    windows_vm=windows_vm
)


# ----------------------------------------------------------------
# Ubuntu instrumentation
# ----------------------------------------------------------------

inetsim = INetSimRunner(
    ubuntu_vm=ubuntu_vm
)

wireshark = WiresharkRunner(
    ubuntu_vm=ubuntu_vm,
    interface="ens33",
)


windows_was_running = windows_vm.is_running()
ubuntu_was_running = ubuntu_vm.is_running()


try:

    # ============================================================
    # Start VMs
    # ============================================================

    windows_vm.start(nogui=False)
    windows_vm.wait_for_guest(shell="windows")

    print("Windows ready")

    ubuntu_vm.start(nogui=True)
    ubuntu_vm.wait_for_guest()

    print("Ubuntu ready")


    # ============================================================
    # Clean previous Windows sample workspace
    # ============================================================

    windows_dispatch.clean_sample_workspace(
        sample_id=SAMPLE_ID,
        sample_variant=VARIANT,
        sha256=SHA256,
    )

    print("Previous Windows sample workspace cleared")


    # ============================================================
    # Prepare Windows output directories
    # ============================================================

    noriben_dir = noriben.prepare_output_dir(
        SAMPLE_ID,
        VARIANT,
        SHA256,
    )

    regshot_dir = regshot.prepare_output_dir(
        SAMPLE_ID,
        VARIANT,
        SHA256,
    )

    sysmon_dir = sysmon.prepare_output_dir(
        SAMPLE_ID,
        VARIANT,
        SHA256,
    )

    print("Windows output directories prepared")


    # ============================================================
    # Prepare Ubuntu output directory
    # ============================================================

    ubuntu.clean_dynamic_workspace(
        sample_id=SAMPLE_ID,
        sample_variant=VARIANT,
        sha256=SHA256,
    )

    print("Previous Ubuntu dynamic workspace cleared")

    ubuntu_dynamic_dir = ubuntu.prepare_dynamic_workspace(
        sample_id=SAMPLE_ID,
        sample_variant=VARIANT,
        sha256=SHA256,
    )

    print("Ubuntu dynamic workspace prepared")


    # ============================================================
    # Reset Sysmon
    # ============================================================

    if not sysmon.is_installed():
        raise RuntimeError("Sysmon is not installed")

    sysmon.clear_log()

    print("Sysmon log cleared")


    # ============================================================
    # Start Ubuntu network instrumentation
    # ============================================================

    inetsim.start(ubuntu_dynamic_dir)

    print("INetSim started")

    pcap_path = wireshark.start(
        ubuntu_dynamic_dir
    )

    print("tshark started")


    # ============================================================
    # Regshot baseline
    # ============================================================

    regshot.start(regshot_dir)

    regshot.take_first_snapshot()

    print("Regshot first snapshot complete")


    # ============================================================
    # Start Noriben
    # ============================================================

    noriben.start(
        noriben_dir,
        timeout=25,
    )

    print("Noriben started")


    # ============================================================
    # Generate benign activity
    # ============================================================

    windows_vm.run_powershell(
        rf'''
New-Item `
    -Path "HKCU:\Software\BinaryEvalIntegrationTest" `
    -Force | Out-Null;

Set-ItemProperty `
    -Path "HKCU:\Software\BinaryEvalIntegrationTest" `
    -Name "TestValue" `
    -Value "Before";

New-Item `
    -ItemType Directory `
    -Path "C:\binary-eval\integration-test" `
    -Force | Out-Null;

Set-Content `
    -Path "C:\binary-eval\integration-test\test.txt" `
    -Value "Windows Ubuntu integration test";

Start-Process `
    "C:\Windows\System32\whoami.exe" `
    -Wait;

Set-ItemProperty `
    -Path "HKCU:\Software\BinaryEvalIntegrationTest" `
    -Name "TestValue" `
    -Value "After";

New-ItemProperty `
    -Path "HKCU:\Software\BinaryEvalIntegrationTest" `
    -Name "AddedValue" `
    -Value "NewData" `
    -Force | Out-Null;

curl.exe `
    --max-time 10 `
    "http://{UBUNTU_IP}/sample.html" `
    -o NUL
'''
    )

    print("Benign local + HTTP activity generated")


    # ============================================================
    # Wait for Noriben
    # ============================================================

    noriben.wait_for_completion()

    print("Noriben complete")


    # ============================================================
    # Regshot second snapshot
    # ============================================================

    regshot.take_second_snapshot()

    print("Regshot second snapshot complete")

    regshot_path = regshot.compare(
        regshot_dir
    )

    print(f"Regshot output: {regshot_path}")


    # ============================================================
    # Export Sysmon
    # ============================================================

    sysmon_path = sysmon.export_log(
        sysmon_dir
    )

    print(f"Sysmon output: {sysmon_path}")


    # ============================================================
    # Stop network capture
    # ============================================================

    wireshark.stop(ubuntu_dynamic_dir)

    print(f"tshark stopped: {pcap_path}")


    # ============================================================
    # Stop INetSim
    # ============================================================

    inetsim.stop()

    print("INetSim stopped")


    # ============================================================
    # Basic Ubuntu artifact validation
    # ============================================================

    ubuntu_vm.run_bash(
        f'test -s "{pcap_path}"'
    )

    print("PCAP exists and is non-empty")


    # ============================================================
    # PASS
    # ============================================================

    print()
    print("Windows + Ubuntu dynamic integration test PASSED")
    print()
    print(f"Noriben: {noriben_dir}")
    print(f"Regshot: {regshot_path}")
    print(f"Sysmon:  {sysmon_path}")
    print(f"PCAP:    {pcap_path}")


finally:

    # ============================================================
    # Cleanup benign Windows activity
    # ============================================================

    try:
        windows_vm.run_powershell(
            '''
Remove-Item `
    "HKCU:\\Software\\BinaryEvalIntegrationTest" `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue;

Remove-Item `
    "C:\\binary-eval\\integration-test" `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue
'''
        )
    except RuntimeError:
        pass


    # ============================================================
    # Emergency collector cleanup
    # ============================================================

    try:
        wireshark.stop(ubuntu_dynamic_dir)
    except RuntimeError:
        pass

    try:
        inetsim.stop()
    except RuntimeError:
        pass

    try:
        regshot.stop()
    except RuntimeError:
        pass


    # ============================================================
    # Restore VM ownership state
    # ============================================================

    if not ubuntu_was_running and ubuntu_vm.is_running():
        try:
            ubuntu_vm.stop(mode="soft")
        except RuntimeError:
            pass

    if not windows_was_running and windows_vm.is_running():
        try:
            windows_vm.stop(mode="soft")
        except RuntimeError:
            pass