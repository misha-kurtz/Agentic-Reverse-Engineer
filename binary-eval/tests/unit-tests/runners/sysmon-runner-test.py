from runners.vmware import VMwareRunner
from runners.sysmon import SysmonRunner


windows_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Windows 11 x64\Windows 11 x64\Windows 11 x64.vmx",
    guest_username=r".\misha.kurtz",
    password_env_var="WINDOWS_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

sysmon_runner = SysmonRunner(windows_vm)

windows_was_running = windows_vm.is_running()

try:
    windows_vm.start(nogui=False)
    windows_vm.wait_for_guest(shell="windows")

    if not sysmon_runner.is_installed():
        raise RuntimeError("Sysmon is not installed")

    print("Sysmon installed")

    output_dir = sysmon_runner.prepare_output_dir(
        "B001",
        "test",
        "test-sha256",
    )

    sysmon_runner.clear_log()
    print("Sysmon log cleared")

    windows_vm.run_powershell(
        'New-Item -Path "HKCU:\\Software\\BinaryEvalSysmonTest" -Force | Out-Null'
    )

    windows_vm.run_powershell(
        'Start-Process "C:\\Windows\\System32\\whoami.exe" -Wait'
    )

    print("Benign activity generated")

    output_path = sysmon_runner.export_log(output_dir)

    print(f"Sysmon EVTX: {output_path}")

finally:
    windows_vm.run_powershell(
        'Remove-Item "HKCU:\\Software\\BinaryEvalSysmonTest" '
        '-Recurse -Force -ErrorAction SilentlyContinue'
    )

    if not windows_was_running and windows_vm.is_running():
        windows_vm.stop(mode="soft")