# binary-eval/noriben-test.py

import time
from pathlib import PureWindowsPath

from runners.vmware import VMwareRunner
from runners.noriben import NoribenRunner


windows_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Windows 11 x64\Windows 11 x64\Windows 11 x64.vmx",
    guest_username=r".\misha.kurtz",
    password_env_var="WINDOWS_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

windows_was_running = windows_vm.is_running()

try:
    windows_vm.start()
    windows_vm.wait_for_guest(shell="windows")

    noriben_runner = NoribenRunner(
        windows_vm=windows_vm,
        python_path=PureWindowsPath(r"C:\Users\misha.kurtz\AppData\Local\Microsoft\WindowsApps\python.exe"),
        noriben_path=PureWindowsPath(r"C:\Users\misha.kurtz\dynamic_analysis\Noriben\Noriben.py"),
    )

    output_dir = noriben_runner.prepare_output_dir(
        sample_id="B001",
        sample_variant="test",
        sha256="test-sha256",
    )

    noriben_runner.start(output_dir, timeout=60)

    time.sleep(3)

    if not noriben_runner.is_running():
        raise RuntimeError("Noriben failed to start")

    print("Noriben is running")

    windows_vm.run_powershell(
        'Start-Process "C:\\Windows\\System32\\notepad.exe"'
    )

    print("Notepad launched")

    noriben_runner.wait_for_completion(timeout=90)

    print("Noriben completed successfully")
    print(f"output_dir: {output_dir}")

finally:
    try:
        noriben_runner.stop()
    except Exception:
        pass

    if not windows_was_running:
        try:
            windows_vm.stop()
        except RuntimeError:
            pass