'''
Milestone: Windows instrumentation coexistence

prepare sample dynamic workspace
        ↓
clear Sysmon log
        ↓
start Regshot
        ↓
Regshot first snapshot
        ↓
start Noriben
        ↓
generate benign activity
        ↓
Noriben naturally times out / completes
        ↓
Regshot second snapshot
        ↓
Regshot compare
        ↓
export Sysmon EVTX
        ↓
verify all 3 artifacts
'''

# binary-eval/windows-instrumentation-test.py

from pathlib import PureWindowsPath

from runners.vmware import VMwareRunner
from runners.noriben import NoribenRunner
from runners.regshot import RegshotRunner
from runners.sysmon import SysmonRunner
from runners.windows_dispatch import WindowsDispatchRunner


SAMPLE_ID = "B001"
VARIANT = "test"
SHA256 = "test-sha256"


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

windows_dispatch = WindowsDispatchRunner(
    windows_vm=windows_vm
)

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

windows_was_running = windows_vm.is_running()


try:
    windows_vm.start(nogui=False)
    windows_vm.wait_for_guest(shell="windows")

    print("Windows ready")

    # ---------------------------------------------------------
    # Clean previous sample workspace
    # ---------------------------------------------------------

    windows_dispatch.clean_sample_workspace(
        sample_id=SAMPLE_ID,
        sample_variant=VARIANT,
        sha256=SHA256,
    )

    print("Previous Windows sample workspace cleared")

    # ---------------------------------------------------------
    # Prepare fresh output directories
    # ---------------------------------------------------------

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

    print("Output directories prepared")

    # ---------------------------------------------------------
    # Reset Sysmon
    # ---------------------------------------------------------

    if not sysmon.is_installed():
        raise RuntimeError("Sysmon is not installed")

    sysmon.clear_log()

    print("Sysmon log cleared")

    # ---------------------------------------------------------
    # Regshot baseline
    # ---------------------------------------------------------

    regshot.start(regshot_dir)
    regshot.take_first_snapshot()

    print("Regshot first snapshot complete")

    # ---------------------------------------------------------
    # Start Noriben
    # ---------------------------------------------------------

    #
    # Use the exact Noriben start call from your working
    # noriben-runner-test.py here.
    #
    noriben.start(
        noriben_dir,
        timeout=20,
    )

    print("Noriben started")

    # ---------------------------------------------------------
    # Benign activity
    # ---------------------------------------------------------

    windows_vm.run_powershell(
        '''
New-Item -Path "HKCU:\\Software\\BinaryEvalInstrumentationTest" `
    -Force | Out-Null;

Set-ItemProperty `
    -Path "HKCU:\\Software\\BinaryEvalInstrumentationTest" `
    -Name "TestValue" `
    -Value "Before";

New-Item `
    -ItemType Directory `
    -Path "C:\\binary-eval\\instrumentation-test" `
    -Force | Out-Null;

Set-Content `
    -Path "C:\\binary-eval\\instrumentation-test\\test.txt" `
    -Value "Binary evaluation instrumentation test";

Start-Process "C:\\Windows\\System32\\whoami.exe" -Wait;

Set-ItemProperty `
    -Path "HKCU:\\Software\\BinaryEvalInstrumentationTest" `
    -Name "TestValue" `
    -Value "After";

New-ItemProperty `
    -Path "HKCU:\\Software\\BinaryEvalInstrumentationTest" `
    -Name "AddedValue" `
    -Value "NewData" `
    -Force | Out-Null
'''
    )

    print("Benign activity generated")

    # ---------------------------------------------------------
    # Wait for Noriben
    # ---------------------------------------------------------

    #
    # Replace this with the exact wait/completion call from
    # your working Noriben runner.
    #
    noriben.wait_for_completion()

    print("Noriben complete")

    # ---------------------------------------------------------
    # Regshot second snapshot + comparison
    # ---------------------------------------------------------

    regshot.take_second_snapshot()

    print("Regshot second snapshot complete")

    regshot_path = regshot.compare(regshot_dir)

    print(f"Regshot output: {regshot_path}")

    # ---------------------------------------------------------
    # Export Sysmon
    # ---------------------------------------------------------

    sysmon_path = sysmon.export_log(sysmon_dir)

    print(f"Sysmon output: {sysmon_path}")

    print()
    print("Windows instrumentation coexistence test passed")

finally:
    # ---------------------------------------------------------
    # Cleanup benign activity
    # ---------------------------------------------------------

    try:
        windows_vm.run_powershell(
            '''
Remove-Item `
    "HKCU:\\Software\\BinaryEvalInstrumentationTest" `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue;

Remove-Item `
    "C:\\binary-eval\\instrumentation-test" `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue
'''
        )
    except RuntimeError:
        pass

    try:
        regshot.stop()
    except RuntimeError:
        pass

    if not windows_was_running and windows_vm.is_running():
        windows_vm.stop(mode="soft")