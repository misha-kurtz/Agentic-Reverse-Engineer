# binary-eval/dynamic-analysis-integration.py

'''
End-to-end dynamic analysis integration test
Input: three bind shell sample variants (original, packed, encrypted)

Malware download from Debian to Windows VM
Default gateway and packet capture from Ubuntu (Tshark, Inetsim server)
Dynamic tools executed on Windows VM (Noriben/Procmon, RegShot, Sysmon)
Execution of malware from Windows VM
Dynamic tools stopped and artifacts uploaded to Debian S3 bucket



Flow:
→ Start Debian
→ Start Ubuntu
→ Start Windows
→ wait_for_guest() all three
→ wait_for_minio()
→ generate presigned URL for selected variant
→ download + SHA256 verify on Windows
→ clean Ubuntu runtime artifacts
→ clean Windows dynamic collector output
→ clean MinIO dynamic prefixes
→ prepare Ubuntu + Windows dynamic workspaces
→ start INetSim
→ start tshark
→ clear Sysmon
→ start Regshot
→ take Regshot snapshot #1
→ start Noriben/Procmon
→ execute malware sample
→ 60-second observation window
→ wait for Noriben to complete Procmon capture
→ take Regshot snapshot #2
→ generate Regshot comparison
→ export Sysmon
→ stop tshark
→ stop INetSim
→ collect INetSim artifacts
→ upload Wireshark
→ upload INetSim
→ upload Noriben
→ upload Regshot
→ upload Sysmon
→ verify MinIO objects
→ stop VMs only if this test started them

IMPORTANT:
Run each variant from the same clean Windows VM snapshot.
'''

import sys
import time

from pathlib import Path, PurePosixPath, PureWindowsPath

from runners.vmware import VMwareRunner
from runners.minio_dispatch import MinioDispatchRunner
from runners.minio_dynamic import MinioDynamicRunner
from runners.windows_dispatch import WindowsDispatchRunner
from runners.ubuntu import UbuntuRunner
from runners.inetsim import INetSimRunner
from runners.wireshark import WiresharkRunner
from runners.noriben import NoribenRunner
from runners.regshot import RegshotRunner
from runners.sysmon import SysmonRunner


SAMPLE_ID = "B001"

SAMPLES = {
    "original": "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59",
    "packed": "7141ef42cb8c213e2ee02cb2ef18e5bf8e862282ab236d39f4115199c16bf402",
    "encrypted": "c1d38e72ae55dc9232c962df041ef5371bf53cce1696867360ebcacd2d914109",
}

EXECUTION_SECONDS = 60
NORIBEN_TIMEOUT = 120


# --------------------------------------------------
# Resolve sample variant
# --------------------------------------------------

if len(sys.argv) != 2:
    raise SystemExit(
        "Usage: python dynamic-analysis-integration.py "
        "<original|packed|encrypted>"
    )

SAMPLE_VARIANT = sys.argv[1].lower()

if SAMPLE_VARIANT not in SAMPLES:
    raise SystemExit(
        f"Invalid sample variant: {SAMPLE_VARIANT}\n"
        f"Valid variants: {', '.join(SAMPLES)}"
    )

SHA256 = SAMPLES[SAMPLE_VARIANT]


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
# Ubuntu INetSim / Gateway VM
# --------------------------------------------------

ubuntu_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway.vmx",
    guest_username="kurtz",
    password_env_var="UBUNTU_GUEST_PASSWORD",
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
ubuntu_was_running = ubuntu_vm.is_running()
windows_was_running = windows_vm.is_running()


# --------------------------------------------------
# Initialize cleanup variables
# --------------------------------------------------

inetsim_runner = None
wireshark_runner = None
noriben_runner = None
regshot_runner = None

ubuntu_dynamic_dir = None
windows_dynamic_dir = None

pcap_output_path = None
inetsim_output_dir = None
noriben_output_dir = None
regshot_output_path = None
sysmon_output_path = None


try:
    # --------------------------------------------------
    # Start required VMs
    # --------------------------------------------------

    print("Starting Debian datapool VM...")
    datapool.start()

    print("Starting Ubuntu INetSim/Gateway VM...")
    ubuntu_vm.start()

    print("Starting Windows dynamic-analysis VM...")
    windows_vm.start(nogui=False)

    # --------------------------------------------------
    # Wait for guest readiness
    # --------------------------------------------------

    print("Waiting for Debian guest...")
    datapool.wait_for_guest()
    print("Debian guest is ready.")

    print("Waiting for Ubuntu guest...")
    ubuntu_vm.wait_for_guest()
    print("Ubuntu guest is ready.")

    print("Waiting for Windows guest...")
    windows_vm.wait_for_guest(shell="windows")
    print("Windows guest is ready.")

    # --------------------------------------------------
    # Instantiate core runners
    # --------------------------------------------------

    minio_dispatch = MinioDispatchRunner(datapool)

    windows_dispatch = WindowsDispatchRunner(
        windows_vm=windows_vm,
    )

    ubuntu_runner = UbuntuRunner(
        ubuntu_vm=ubuntu_vm,
    )

    inetsim_runner = INetSimRunner(
        ubuntu_vm=ubuntu_vm,
    )

    wireshark_runner = WiresharkRunner(
        ubuntu_vm=ubuntu_vm,
        interface="ens33",
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

    sysmon_runner = SysmonRunner(windows_vm=windows_vm)

    # --------------------------------------------------
    # Instantiate MinIO dynamic upload runners
    # --------------------------------------------------

    inetsim_minio_runner = MinioDynamicRunner(
        vm=ubuntu_vm,
        alias="datapool-inetsim",
        platform="linux",
    )

    pcap_minio_runner = MinioDynamicRunner(
        vm=ubuntu_vm,
        alias="datapool-pcap",
        platform="linux",
    )

    windows_minio_runner = MinioDynamicRunner(
        vm=windows_vm,
        alias="datapool",
        platform="windows",
    )

    # --------------------------------------------------
    # Wait for MinIO readiness
    # --------------------------------------------------

    print("Waiting for MinIO...")
    minio_dispatch.wait_for_minio()
    print("MinIO is ready.")

    print()
    print("=== Selected Sample ===")
    print(f"sample_id: {SAMPLE_ID}")
    print(f"variant: {SAMPLE_VARIANT}")
    print(f"sha256: {SHA256}")
    print()

    # --------------------------------------------------
    # Clean previous Windows sample workspace
    #
    # Do this BEFORE downloading the new sample.
    # --------------------------------------------------

    print("Cleaning previous Windows sample workspace...")

    windows_dispatch.clean_sample_workspace(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    # --------------------------------------------------
    # Generate presigned URL
    # --------------------------------------------------

    print("Generating presigned sample URL...")

    host_temp_url_path = Path(
        r"C:\Users\MK\AppData\Local\Temp\presigned_url.txt"
    )

    presigned_url = minio_dispatch.generate_presigned_url(
        sample_id=SAMPLE_ID,
        sha256=SHA256,
        sample_variant=SAMPLE_VARIANT,
        host_temp_path=host_temp_url_path,
    )

    print("Presigned URL generated.")

    # --------------------------------------------------
    # Download sample to Windows and verify SHA256
    # --------------------------------------------------

    guest_sample_path = PureWindowsPath(
        rf"C:\binary-eval\work\{SAMPLE_ID}"
        rf"\{SAMPLE_VARIANT}\{SHA256}"
        rf"\sample.exe"
    )

    print("Downloading sample to Windows VM...")

    windows_dispatch.download_and_verify(
        presigned_url=presigned_url,
        expected_sha256=SHA256,
        guest_sample_path=guest_sample_path,
    )

    print("Sample downloaded and SHA256 verified.")

    # --------------------------------------------------
    # Clean Ubuntu workspace
    # --------------------------------------------------

    print("Cleaning Ubuntu dynamic workspace...")

    ubuntu_runner.clean_dynamic_workspace(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    # --------------------------------------------------
    # Clean INetSim runtime artifacts
    # --------------------------------------------------

    print("Cleaning INetSim runtime artifacts...")
    inetsim_runner.clean_runtime_artifacts()

    # --------------------------------------------------
    # Clean previous MinIO dynamic artifacts
    # --------------------------------------------------

    print("Cleaning previous Wireshark MinIO prefix...")

    pcap_minio_runner.clean_directory_prefix(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="wireshark",
    )

    print("Cleaning previous INetSim MinIO prefix...")

    inetsim_minio_runner.clean_directory_prefix(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="inetsim",
    )

    print("Cleaning previous Noriben MinIO prefix...")

    windows_minio_runner.clean_directory_prefix(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="noriben",
    )

    print("Cleaning previous Regshot MinIO prefix...")

    windows_minio_runner.clean_directory_prefix(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="regshot",
    )

    print("Cleaning previous Sysmon MinIO prefix...")

    windows_minio_runner.clean_directory_prefix(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="sysmon",
    )

    # --------------------------------------------------
    # Prepare Ubuntu dynamic workspace
    # --------------------------------------------------

    print("Preparing Ubuntu dynamic workspace...")

    ubuntu_dynamic_dir = ubuntu_runner.prepare_dynamic_workspace(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    print(f"Ubuntu dynamic workspace: {ubuntu_dynamic_dir}")

    # --------------------------------------------------
    # Prepare Windows dynamic output directories
    # --------------------------------------------------

    print("Preparing Windows dynamic output directories...")

    noriben_output_dir = noriben_runner.prepare_output_dir(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    regshot_output_dir = regshot_runner.prepare_output_dir(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    sysmon_output_dir = sysmon_runner.prepare_output_dir(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    windows_dynamic_dir = PureWindowsPath(
        rf"C:\binary-eval\work\{SAMPLE_ID}"
        rf"\{SAMPLE_VARIANT}\{SHA256}"
        rf"\dynamic"
    )

    print(f"Windows dynamic workspace: {windows_dynamic_dir}")

    # --------------------------------------------------
    # Verify Sysmon
    # --------------------------------------------------

    print("Verifying Sysmon installation...")

    if not sysmon_runner.is_installed():
        raise RuntimeError("Sysmon is not installed")

    print("Sysmon verified.")

    # --------------------------------------------------
    # Start INetSim
    # --------------------------------------------------

    print("Starting INetSim...")

    inetsim_runner.start(
        dynamic_dir=ubuntu_dynamic_dir,
    )

    if not inetsim_runner.is_running():
        raise RuntimeError("INetSim failed to start")

    print("INetSim is running.")

    # --------------------------------------------------
    # Start Wireshark / tshark
    # --------------------------------------------------

    print("Starting packet capture...")

    pcap_output_path = wireshark_runner.start(
        dynamic_dir=ubuntu_dynamic_dir,
    )

    time.sleep(2)

    if not wireshark_runner.is_running(
        ubuntu_dynamic_dir
    ):
        raise RuntimeError(
            "Wireshark/tshark failed to start"
        )

    print("Packet capture is running.")

    # --------------------------------------------------
    # Clear Sysmon immediately before observation
    # --------------------------------------------------

    print("Clearing Sysmon event log...")
    sysmon_runner.clear_log()


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
    # Take baseline Regshot snapshot
    # --------------------------------------------------

    print("Taking first Regshot snapshot...")

    regshot_runner.take_first_snapshot()

    print("First Regshot snapshot complete.")


    # --------------------------------------------------
    # Start Noriben
    # --------------------------------------------------

    print("Starting Noriben...")

    noriben_runner.start(
        output_dir=noriben_output_dir,
        timeout=NORIBEN_TIMEOUT,
    )

    time.sleep(3)

    if not noriben_runner.is_running():
        raise RuntimeError("Noriben failed to start")

    print("Noriben is running.")


    # --------------------------------------------------
    # Execute malware sample
    # --------------------------------------------------

    print()
    print("=== Executing Malware Sample ===")
    print(f"variant: {SAMPLE_VARIANT}")
    print(f"path: {guest_sample_path}")

    windows_vm.run_powershell(
        f'Start-Process -FilePath "{guest_sample_path}"'
    )

    print("Sample launched.")

    # --------------------------------------------------
    # Observation window
    # --------------------------------------------------

    print(
        f"Observing malware for "
        f"{EXECUTION_SECONDS} seconds..."
    )

    time.sleep(EXECUTION_SECONDS)

    print("Observation window complete.")

    # --------------------------------------------------
    # Wait for Noriben completion
    # --------------------------------------------------

    print("Waiting for Noriben completion...")

    noriben_runner.wait_for_completion(
        timeout=NORIBEN_TIMEOUT + 60,
    )

    print("Noriben completed.")


    # --------------------------------------------------
    # Regshot second snapshot
    # --------------------------------------------------

    print("Taking second Regshot snapshot...")

    regshot_runner.take_second_snapshot()

    print("Second Regshot snapshot complete.")


    # --------------------------------------------------
    # Generate Regshot comparison
    # --------------------------------------------------

    print("Generating Regshot comparison report...")

    regshot_output_path = regshot_runner.compare(
        output_dir=regshot_output_dir,
    )

    print(f"Regshot output path: {regshot_output_path}")


    # --------------------------------------------------
    # Export Sysmon
    # --------------------------------------------------

    print("Exporting Sysmon event log...")

    sysmon_output_path = sysmon_runner.export_log(
        output_dir=sysmon_output_dir,
    )

    print(f"Sysmon output path: {sysmon_output_path}")

    # --------------------------------------------------
    # Stop Wireshark
    # --------------------------------------------------

    print("Stopping packet capture...")

    wireshark_runner.stop(
        dynamic_dir=ubuntu_dynamic_dir,
    )

    if wireshark_runner.is_running(
        ubuntu_dynamic_dir
    ):
        raise RuntimeError(
            "Wireshark/tshark is still running after stop"
        )

    print("Packet capture stopped.")

    # --------------------------------------------------
    # Stop INetSim
    # --------------------------------------------------

    print("Stopping INetSim...")

    inetsim_runner.stop()

    if inetsim_runner.is_running():
        raise RuntimeError(
            "INetSim is still running after stop"
        )

    print("INetSim stopped.")

    # --------------------------------------------------
    # Collect INetSim artifacts
    # --------------------------------------------------

    print("Collecting INetSim artifacts...")

    inetsim_output_dir = inetsim_runner.collect_artifacts(
        dynamic_dir=ubuntu_dynamic_dir,
    )

    print(
        f"INetSim artifact directory: "
        f"{inetsim_output_dir}"
    )

    # --------------------------------------------------
    # Verify generated artifacts before upload
    # --------------------------------------------------

    print("Verifying PCAP artifact...")

    ubuntu_vm.run_bash(
        f'test -f "{pcap_output_path}"'
    )

    print("Verifying INetSim artifacts...")

    ubuntu_vm.run_bash(
        f'test -d "{inetsim_output_dir}"'
    )

    print("Verifying Noriben artifacts...")

    windows_vm.run_powershell(
        f'if (-not (Test-Path "{noriben_output_dir}")) '
        f'{{ exit 1 }}'
    )

    print("Verifying Regshot artifact...")

    windows_vm.run_powershell(
        f'if (-not (Test-Path "{regshot_output_path}")) '
        f'{{ exit 1 }}'
    )

    print("Verifying Sysmon artifact...")

    windows_vm.run_powershell(
        f'if (-not (Test-Path "{sysmon_output_path}")) '
        f'{{ exit 1 }}'
    )

    # --------------------------------------------------
    # Upload Wireshark
    # --------------------------------------------------

    print("Uploading Wireshark PCAP...")

    pcap_minio_runner.upload(
        guest_artifact_path=pcap_output_path,
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        artifact_name="wireshark/traffic.pcapng",
    )

    print("Wireshark upload complete.")

    # --------------------------------------------------
    # Upload INetSim
    # --------------------------------------------------

    print("Uploading INetSim artifacts...")

    inetsim_minio_runner.upload_directory(
        guest_directory_path=inetsim_output_dir,
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="inetsim",
    )

    print("INetSim upload complete.")

    # --------------------------------------------------
    # Upload Noriben
    # --------------------------------------------------

    print("Uploading Noriben artifacts...")

    windows_minio_runner.upload_directory(
        guest_directory_path=noriben_output_dir,
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="noriben",
    )

    print("Noriben upload complete.")

    # --------------------------------------------------
    # Upload Regshot
    # --------------------------------------------------

    print("Uploading Regshot artifact...")

    windows_minio_runner.upload(
        guest_artifact_path=regshot_output_path,
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        artifact_name=(
            f"regshot/{regshot_output_path.name}"
        ),
    )

    print("Regshot upload complete.")

    # --------------------------------------------------
    # Upload Sysmon
    # --------------------------------------------------

    print("Uploading Sysmon artifact...")

    windows_minio_runner.upload(
        guest_artifact_path=sysmon_output_path,
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        artifact_name="sysmon/sysmon.evtx",
    )

    print("Sysmon upload complete.")

    # --------------------------------------------------
    # Verify MinIO artifacts
    # --------------------------------------------------

    base_destination = (
        f"datapool/dynamic/"
        f"{SAMPLE_ID}/"
        f"{SAMPLE_VARIANT}/"
        f"{SHA256}"
    )

    print("Verifying Wireshark object in MinIO...")

    ubuntu_vm.run_bash(
        f'mc stat '
        f'"datapool-pcap/dynamic/'
        f'{SAMPLE_ID}/'
        f'{SAMPLE_VARIANT}/'
        f'{SHA256}/'
        f'wireshark/traffic.pcapng"'
    )

    print("Verifying INetSim objects in MinIO...")

    ubuntu_vm.run_bash(
        f'mc ls --recursive '
        f'"datapool-inetsim/dynamic/'
        f'{SAMPLE_ID}/'
        f'{SAMPLE_VARIANT}/'
        f'{SHA256}/'
        f'inetsim/"'
    )

    print("Verifying Noriben objects in MinIO...")

    windows_vm.run_powershell(
        f'mc ls --recursive '
        f'"{base_destination}/noriben/"'
    )

    print("Verifying Regshot object in MinIO...")

    windows_vm.run_powershell(
        f'mc stat '
        f'"{base_destination}/regshot/'
        f'{regshot_output_path.name}"'
    )

    print("Verifying Sysmon object in MinIO...")

    windows_vm.run_powershell(
        f'mc stat '
        f'"{base_destination}/sysmon/sysmon.evtx"'
    )

    # --------------------------------------------------
    # Final result
    # --------------------------------------------------

    print()
    print("=== Dynamic Analysis Integration Test Complete ===")
    print(f"sample_id: {SAMPLE_ID}")
    print(f"variant: {SAMPLE_VARIANT}")
    print(f"sha256: {SHA256}")
    print(f"windows_sample_path: {guest_sample_path}")
    print(f"ubuntu_dynamic_dir: {ubuntu_dynamic_dir}")
    print(f"windows_dynamic_dir: {windows_dynamic_dir}")
    print(f"pcap_output_path: {pcap_output_path}")
    print(f"inetsim_output_dir: {inetsim_output_dir}")
    print(f"noriben_output_dir: {noriben_output_dir}")
    print(f"regshot_output_path: {regshot_output_path}")
    print(f"sysmon_output_path: {sysmon_output_path}")
    print("sample_downloaded: True")
    print("sha256_verified: True")
    print("sample_executed: True")
    print("wireshark_upload_complete: True")
    print("inetsim_upload_complete: True")
    print("noriben_upload_complete: True")
    print("regshot_upload_complete: True")
    print("sysmon_upload_complete: True")


finally:
    # --------------------------------------------------
    # Best-effort collector cleanup
    # --------------------------------------------------

    if noriben_runner is not None:
        try:
            if noriben_runner.is_running():
                noriben_runner.stop()
        except Exception:
            pass

    if regshot_runner is not None:
        try:
            if regshot_runner.is_running():
                regshot_runner.stop()
        except Exception:
            pass

    if wireshark_runner is not None and ubuntu_dynamic_dir is not None:
        try:
            if wireshark_runner.is_running(
                ubuntu_dynamic_dir
            ):
                wireshark_runner.stop(
                    ubuntu_dynamic_dir
                )
        except Exception:
            pass

    if inetsim_runner is not None:
        try:
            if inetsim_runner.is_running():
                inetsim_runner.stop()
        except Exception:
            pass

    # --------------------------------------------------
    # Stop VMs only if this test started them
    # --------------------------------------------------

    if not windows_was_running:
        try:
            windows_vm.stop()
        except RuntimeError:
            pass

    if not ubuntu_was_running:
        try:
            ubuntu_vm.stop()
        except RuntimeError:
            pass

    if not datapool_was_running:
        try:
            datapool.stop()
        except RuntimeError:
            pass