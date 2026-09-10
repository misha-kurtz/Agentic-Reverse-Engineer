from pathlib import PureWindowsPath

from runners.vmware import VMwareRunner
from runners.regshot import RegshotRunner


windows_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Windows 11 x64\Windows 11 x64\Windows 11 x64.vmx",
    guest_username=r".\misha.kurtz",
    password_env_var="WINDOWS_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

windows_was_running = windows_vm.is_running()

regshot_runner = RegshotRunner(
    windows_vm=windows_vm,
    python_path=PureWindowsPath(r"C:\Users\misha.kurtz\AppData\Local\Microsoft\WindowsApps\python.exe"),
    regshot_path=PureWindowsPath(r"C:\Users\misha.kurtz\dynamic_analysis\Regshot-1.9.0\Regshot-x64-Unicode.exe"),
)

try:
    windows_vm.start(nogui=False)
    windows_vm.wait_for_guest(shell="windows")

    output_dir = regshot_runner.prepare_output_dir(
        sample_id="B001",
        sample_variant="test",
        sha256="test-sha256",
    )

    print(f"Regshot output directory: {output_dir}")

    regshot_runner.start(output_dir)

    print("Regshot started")

    regshot_runner.take_first_snapshot()

    print("First snapshot complete")

    windows_vm.run_powershell(
        'New-Item -Path "HKCU:\\Software\\BinaryEvalRegshotTest" -Force | Out-Null; '
        'New-ItemProperty -Path "HKCU:\\Software\\BinaryEvalRegshotTest" '
        '-Name "TestValue" -Value "Before" -PropertyType String -Force | Out-Null'
    )

    print("Benign registry key created")

    windows_vm.run_powershell(
        'Set-ItemProperty -Path "HKCU:\\Software\\BinaryEvalRegshotTest" '
        '-Name "TestValue" -Value "After"; '
        'New-ItemProperty -Path "HKCU:\\Software\\BinaryEvalRegshotTest" '
        '-Name "AddedValue" -Value "NewData" -PropertyType String -Force | Out-Null'
    )

    print("Benign registry values modified")

    regshot_runner.take_second_snapshot()

    print("Second snapshot complete")

    diff_path = regshot_runner.compare(output_dir)

    print("Regshot comparison complete")
    print(f"diff_path: {diff_path}")

finally:
    try:
        windows_vm.run_powershell(
            'Remove-Item -Path "HKCU:\\Software\\BinaryEvalRegshotTest" '
            '-Recurse -Force -ErrorAction SilentlyContinue'
        )
    except RuntimeError:
        pass

    try:
        if regshot_runner.is_running():
            regshot_runner.stop()
    except RuntimeError:
        pass

    if not windows_was_running:
        try:
            windows_vm.stop()
        except RuntimeError:
            pass