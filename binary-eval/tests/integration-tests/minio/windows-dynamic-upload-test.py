# binary-eval/windows-dynamic-upload-test.py

'''
Integration test for Windows dynamic artifact collection
and upload to Debian MinIO S3 bucket.

Flow:
→ Start Debian datapool VM
→ Start Windows 11 dynamic-analysis VM
→ Wait for both guests
→ Wait for MinIO readiness
→ Clean Windows dynamic workspace
→ Clean MinIO artifact prefixes
→ Prepare Noriben output directory
→ Prepare Regshot output directory
→ Prepare Sysmon output directory
→ Verify Sysmon installation
→ Clear Sysmon event log
→ Start Noriben
→ Start Regshot
→ Take first Regshot snapshot
→ Generate benign Windows test activity
→ Allow collectors to run
→ Take second Regshot snapshot
→ Generate Regshot comparison report
→ Wait for Noriben completion
→ Export Sysmon event log
→ Verify generated artifacts
→ Upload Noriben directory
→ Upload Regshot report
→ Upload Sysmon EVTX
→ Verify uploaded MinIO objects
→ Clean up collectors and benign test artifacts
→ Stop VMs only if this test started them
'''

import time

from pathlib import PureWindowsPath

from runners.vmware import VMwareRunner
from runners.windows_dispatch import WindowsDispatchRunner
from runners.noriben import NoribenRunner
from runners.regshot import RegshotRunner
from runners.sysmon import SysmonRunner
from runners.minio_dynamic import MinioDynamicRunner
from runners.minio_dispatch import MinioDispatchRunner


SAMPLE_ID = "B001"
SAMPLE_VARIANT = "original"
SHA256 = "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59"

EXECUTION_SECONDS = 15


# --------------------------------------------------
# Debian Datapool VM
# --------------------------------------------------

datapool = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server.vmx",
    guest_username="kurtz",
    password_env_var="DATAPOOL_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)


# --------------------------------------------------
# Windows Dynamic Analysis VM
# --------------------------------------------------

windows_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Windows 11 x64\Windows 11 x64\Windows 11 x64.vmx",
    guest_username=r".\misha.kurtz",
    password_env_var="WINDOWS_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)


# --------------------------------------------------
# Record initial VM state
# --------------------------------------------------

datapool_was_running = datapool.is_running()
windows_was_running = windows_vm.is_running()

# Initialize cleanup variables in case startup fails
noriben_runner = None
regshot_runner = None
test_file = None


try:
    # --------------------------------------------------
    # Start required VMs
    # --------------------------------------------------

    print("Starting Debian datapool VM...")
    datapool.start()

    print("Starting Windows dynamic-analysis VM...")
    windows_vm.start()

    # --------------------------------------------------
    # Wait for VMware Tools / guest readiness
    # --------------------------------------------------

    print("Waiting for Debian guest...")
    datapool.wait_for_guest()
    print("Debian guest is ready.")

    print("Waiting for Windows guest...")
    windows_vm.wait_for_guest(shell="windows")
    print("Windows guest is ready.")

    # --------------------------------------------------
    # Verify MinIO service readiness on Debian
    # --------------------------------------------------

    print("Waiting for MinIO...")

    minio_dispatch = MinioDispatchRunner(datapool)
    minio_dispatch.wait_for_minio()

    print("MinIO is ready.")

    # --------------------------------------------------
    # Instantiate runners
    # --------------------------------------------------

    windows_dispatch = WindowsDispatchRunner(
        windows_vm=windows_vm,
    )

    noriben_runner = NoribenRunner(
        windows_vm=windows_vm,
        python_path=PureWindowsPath(r"C:\Users\misha.kurtz\AppData\Local\Microsoft\WindowsApps\python.exe"),
        noriben_path=PureWindowsPath(r"C:\Users\misha.kurtz\dynamic_analysis\Noriben\Noriben.py"),
    )

    regshot_runner = RegshotRunner(
        windows_vm=windows_vm,
        python_path=PureWindowsPath(r"C:\Users\misha.kurtz\AppData\Local\Microsoft\WindowsApps\python.exe"),
        regshot_path=PureWindowsPath(r"C:\Users\misha.kurtz\dynamic_analysis\Regshot-1.9.0\Regshot-x64-Unicode.exe"),
    )

    sysmon_runner = SysmonRunner(
        windows_vm=windows_vm,
    )

    windows_minio_runner = MinioDynamicRunner(
        vm=windows_vm,
        alias="datapool",
        platform="windows",
    )

    # --------------------------------------------------
    # Clean Windows sample workspace
    # --------------------------------------------------

    print("Cleaning Windows dynamic workspace...")

    windows_dispatch.clean_sample_workspace(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    # --------------------------------------------------
    # Clean existing MinIO Windows artifact prefixes
    # --------------------------------------------------

    print("Cleaning existing Noriben MinIO prefix...")

    windows_minio_runner.clean_directory_prefix(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="noriben",
    )

    print("Cleaning existing Regshot MinIO prefix...")

    windows_minio_runner.clean_directory_prefix(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="regshot",
    )

    print("Cleaning existing Sysmon MinIO prefix...")

    windows_minio_runner.clean_directory_prefix(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="sysmon",
    )

    # --------------------------------------------------
    # Prepare output directories
    # --------------------------------------------------

    print("Preparing Noriben output directory...")

    noriben_output_dir = noriben_runner.prepare_output_dir(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    print(f"Noriben output directory: {noriben_output_dir}")

    print("Preparing Regshot output directory...")

    regshot_output_dir = regshot_runner.prepare_output_dir(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    print(f"Regshot output directory: {regshot_output_dir}")

    print("Preparing Sysmon output directory...")

    sysmon_output_dir = sysmon_runner.prepare_output_dir(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    print(f"Sysmon output directory: {sysmon_output_dir}")

    # --------------------------------------------------
    # Verify Sysmon
    # --------------------------------------------------

    print("Verifying Sysmon installation...")

    if not sysmon_runner.is_installed():
        raise RuntimeError("Sysmon is not installed or its service could not be found")

    print("Sysmon verified.")

    # --------------------------------------------------
    # Clear Sysmon event log
    # --------------------------------------------------

    print("Clearing Sysmon event log...")
    sysmon_runner.clear_log()

    # --------------------------------------------------
    # Start Noriben
    # --------------------------------------------------

    print("Starting Noriben...")

    noriben_runner.start(
        output_dir=noriben_output_dir,
        timeout=EXECUTION_SECONDS,
    )

    time.sleep(2)

    if not noriben_runner.is_running():
        raise RuntimeError("Noriben failed to start")

    print("Noriben is running.")

    # --------------------------------------------------
    # Start Regshot
    # --------------------------------------------------

    print("Starting Regshot...")

    regshot_runner.start(
        output_dir=regshot_output_dir,
    )

    if not regshot_runner.is_running():
        raise RuntimeError("Regshot failed to start")

    print("Regshot is running.")

    # --------------------------------------------------
    # Take first Regshot snapshot
    # --------------------------------------------------

    print("Taking first Regshot snapshot...")

    regshot_runner.take_first_snapshot()

    print("First Regshot snapshot complete.")

    # --------------------------------------------------
    # Generate benign Windows activity
    # --------------------------------------------------

    print("Generating benign Windows test activity...")

    test_file = PureWindowsPath(
        rf"C:\binary-eval\work\{SAMPLE_ID}"
        rf"\{SAMPLE_VARIANT}\{SHA256}"
        rf"\dynamic\windows-upload-test.txt"
    )

    windows_vm.run_powershell(
        f'"Windows dynamic upload integration test" '
        f'| Set-Content "{test_file}"; '
        f'New-Item '
        f'-Path "HKCU:\\Software\\BinaryEvalUploadTest" '
        f'-Force | Out-Null; '
        f'New-ItemProperty '
        f'-Path "HKCU:\\Software\\BinaryEvalUploadTest" '
        f'-Name "TestValue" '
        f'-Value "DynamicUploadTest" '
        f'-PropertyType String '
        f'-Force | Out-Null'
    )

    print(f"Allowing dynamic collectors to run for {EXECUTION_SECONDS} seconds...")
    time.sleep(EXECUTION_SECONDS)

    # --------------------------------------------------
    # Take second Regshot snapshot
    # --------------------------------------------------

    print("Taking second Regshot snapshot...")

    regshot_runner.take_second_snapshot()

    print("Second Regshot snapshot complete.")

    # --------------------------------------------------
    # Compare Regshot snapshots
    # --------------------------------------------------

    print("Generating Regshot comparison report...")

    regshot_output_path = regshot_runner.compare(
        output_dir=regshot_output_dir,
    )

    print(f"Regshot output path: {regshot_output_path}")

    # --------------------------------------------------
    # Wait for Noriben completion
    # --------------------------------------------------

    print("Waiting for Noriben completion...")

    noriben_runner.wait_for_completion(
        timeout=EXECUTION_SECONDS + 60,
    )

    print("Noriben completed.")

    # --------------------------------------------------
    # Export Sysmon log
    # --------------------------------------------------

    print("Exporting Sysmon event log...")

    sysmon_output_path = sysmon_runner.export_log(
        output_dir=sysmon_output_dir,
    )

    print(f"Sysmon output path: {sysmon_output_path}")

    # --------------------------------------------------
    # Verify Noriben output
    # --------------------------------------------------

    print("Verifying Noriben output directory...")

    windows_vm.run_powershell(
        f'if (-not (Test-Path "{noriben_output_dir}")) {{ exit 1 }}'
    )

    # --------------------------------------------------
    # Verify Regshot output
    # --------------------------------------------------

    print("Verifying Regshot output...")

    windows_vm.run_powershell(
        f'if (-not (Test-Path "{regshot_output_path}")) {{ exit 1 }}'
    )

    # --------------------------------------------------
    # Verify Sysmon output
    # --------------------------------------------------

    print("Verifying Sysmon output...")

    windows_vm.run_powershell(
        f'if (-not (Test-Path "{sysmon_output_path}")) {{ exit 1 }}'
    )

    # --------------------------------------------------
    # Upload Noriben directory
    # --------------------------------------------------

    print("Uploading Noriben artifacts to MinIO...")

    windows_minio_runner.upload_directory(
        guest_directory_path=noriben_output_dir,
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="noriben",
    )

    print("Noriben upload complete.")

    # --------------------------------------------------
    # Upload Regshot report
    # --------------------------------------------------

    print("Uploading Regshot artifact to MinIO...")

    windows_minio_runner.upload(
        guest_artifact_path=regshot_output_path,
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        artifact_name=f"regshot/{regshot_output_path.name}",
    )

    print("Regshot upload complete.")

    # --------------------------------------------------
    # Upload Sysmon EVTX
    # --------------------------------------------------

    print("Uploading Sysmon artifact to MinIO...")

    windows_minio_runner.upload(
        guest_artifact_path=sysmon_output_path,
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        artifact_name="sysmon/sysmon.evtx",
    )

    print("Sysmon upload complete.")

    # --------------------------------------------------
    # Verify uploaded objects in MinIO
    # --------------------------------------------------

    base_destination = (
        f"datapool/dynamic/"
        f"{SAMPLE_ID}/"
        f"{SAMPLE_VARIANT}/"
        f"{SHA256}"
    )

    print("Verifying Noriben objects in MinIO...")

    windows_vm.run_powershell(
        f'mc ls --recursive "{base_destination}/noriben/"'
    )

    print("Verifying Regshot object in MinIO...")

    windows_vm.run_powershell(
        f'mc stat "{base_destination}/regshot/{regshot_output_path.name}"'
    )

    print("Verifying Sysmon object in MinIO...")

    windows_vm.run_powershell(
        f'mc stat "{base_destination}/sysmon/sysmon.evtx"'
    )

    # --------------------------------------------------
    # Final result
    # --------------------------------------------------

    print()
    print("=== Windows Dynamic Integration Test ===")
    print(f"sample_id: {SAMPLE_ID}")
    print(f"variant: {SAMPLE_VARIANT}")
    print(f"sha256: {SHA256}")
    print(f"noriben_output_dir: {noriben_output_dir}")
    print(f"regshot_output_path: {regshot_output_path}")
    print(f"sysmon_output_path: {sysmon_output_path}")
    print("datapool_vm_ready: True")
    print("windows_vm_ready: True")
    print("minio_ready: True")
    print("noriben_upload_complete: True")
    print("regshot_upload_complete: True")
    print("sysmon_upload_complete: True")


finally:
    # --------------------------------------------------
    # Best-effort Noriben cleanup
    # --------------------------------------------------

    if noriben_runner is not None:
        try:
            if noriben_runner.is_running():
                noriben_runner.stop()
        except Exception:
            pass

    # --------------------------------------------------
    # Best-effort Regshot cleanup
    # --------------------------------------------------

    if regshot_runner is not None:
        try:
            if regshot_runner.is_running():
                regshot_runner.stop()
        except Exception:
            pass

    # --------------------------------------------------
    # Remove benign test artifacts
    # --------------------------------------------------

    if test_file is not None:
        try:
            windows_vm.run_powershell(
                f'Remove-Item "{test_file}" '
                f'-Force -ErrorAction SilentlyContinue; '
                f'Remove-Item '
                f'"HKCU:\\Software\\BinaryEvalUploadTest" '
                f'-Recurse -Force -ErrorAction SilentlyContinue'
            )
        except Exception:
            pass

    # --------------------------------------------------
    # Stop Windows only if test started it
    # --------------------------------------------------

    if not windows_was_running:
        try:
            windows_vm.stop()
        except RuntimeError:
            pass

    # --------------------------------------------------
    # Stop Debian only if test started it
    # --------------------------------------------------

    if not datapool_was_running:
        try:
            datapool.stop()
        except RuntimeError:
            pass