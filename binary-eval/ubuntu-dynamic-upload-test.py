# binary-eval/ubuntu-dynamic-upload-test.py

'''
Integration test for upload of dynamic
networking artifacts from Ubuntu Inetsim 
server to Debian MinIO S3 bucket

→ INetSim runtime cleanup
→ MinIO prefix cleanup
→ workspace creation
→ start INetSim
→ start Wireshark/tshark
→ wait briefly for collection
→ stop Wireshark
→ stop INetSim
→ collect INetSim artifacts
→ upload PCAP
→ upload INetSim directory
'''
import time

from runners.vmware import VMwareRunner
from runners.ubuntu import UbuntuRunner
from runners.inetsim import INetSimRunner
from runners.wireshark import WiresharkRunner
from runners.minio_dynamic import MinioDynamicRunner


SAMPLE_ID = "B001"
SAMPLE_VARIANT = "original"
SHA256 = "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59"

EXECUTION_SECONDS = 15


ubuntu_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway.vmx",
    guest_username="kurtz",
    password_env_var="UBUNTU_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)


ubuntu_was_running = ubuntu_vm.is_running()


try:
    # --------------------------------------------------
    # Start Ubuntu VM
    # --------------------------------------------------
    ubuntu_vm.start()
    ubuntu_vm.wait_for_guest()

    # --------------------------------------------------
    # Instantiate runners
    # --------------------------------------------------
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

    inetsim_minio_runner = MinioDynamicRunner(
        vm=ubuntu_vm,
        alias="datapool-inetsim",
    )

    pcap_minio_runner = MinioDynamicRunner(
        vm=ubuntu_vm,
        alias="datapool-pcap",
    )

    # --------------------------------------------------
    # Clean Ubuntu workspace from previous run
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
    # Clean existing MinIO dynamic artifacts
    # --------------------------------------------------
    print("Cleaning existing INetSim MinIO prefix...")

    inetsim_minio_runner.clean_directory_prefix(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="inetsim",
    )

    print("Cleaning existing Wireshark MinIO prefix...")

    pcap_minio_runner.clean_directory_prefix(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="wireshark",
    )

    # --------------------------------------------------
    # Prepare Ubuntu dynamic workspace
    # --------------------------------------------------
    print("Preparing Ubuntu dynamic workspace...")

    dynamic_dir = ubuntu_runner.prepare_dynamic_workspace(
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
    )

    print(f"Dynamic workspace: {dynamic_dir}")

    # --------------------------------------------------
    # Start INetSim
    # --------------------------------------------------
    print("Starting INetSim...")

    inetsim_runner.start(
        dynamic_dir=dynamic_dir,
    )

    if not inetsim_runner.is_running():
        raise RuntimeError(
            "INetSim failed to start"
        )

    print("INetSim is running.")

    # --------------------------------------------------
    # Start Wireshark/tshark capture
    # --------------------------------------------------
    print("Starting packet capture...")

    pcap_output_path = wireshark_runner.start(
        dynamic_dir=dynamic_dir,
    )

    time.sleep(2)

    if not wireshark_runner.is_running(dynamic_dir):
        raise RuntimeError(
            "Wireshark/tshark failed to start"
        )

    print(f"PCAP output path: {pcap_output_path}")

    # --------------------------------------------------
    # Observation period
    #
    # Later, Windows malware execution will occur here.
    # For this Ubuntu-only integration test, simply allow
    # INetSim and tshark to run briefly.
    # --------------------------------------------------
    print(
        f"Collecting for {EXECUTION_SECONDS} seconds..."
    )

    time.sleep(EXECUTION_SECONDS)

    # --------------------------------------------------
    # Stop Wireshark
    # --------------------------------------------------
    print("Stopping packet capture...")

    wireshark_runner.stop(
        dynamic_dir=dynamic_dir,
    )

    if wireshark_runner.is_running(dynamic_dir):
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
    # Collect INetSim artifacts into sample workspace
    # --------------------------------------------------
    print("Collecting INetSim artifacts...")

    inetsim_output_dir = inetsim_runner.collect_artifacts(
        dynamic_dir=dynamic_dir,
    )

    print(
        f"INetSim artifact directory: "
        f"{inetsim_output_dir}"
    )

    # --------------------------------------------------
    # Verify PCAP exists before upload
    # --------------------------------------------------
    print("Verifying PCAP artifact exists...")

    ubuntu_vm.run_bash(
        f'test -f "{pcap_output_path}"'
    )

    # --------------------------------------------------
    # Verify INetSim directory exists before upload
    # --------------------------------------------------
    print("Verifying INetSim artifact directory exists...")

    ubuntu_vm.run_bash(
        f'test -d "{inetsim_output_dir}"'
    )

    # --------------------------------------------------
    # Upload Wireshark PCAP
    # --------------------------------------------------
    print("Uploading Wireshark PCAP to MinIO...")

    pcap_minio_runner.upload(
        guest_artifact_path=pcap_output_path,
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        artifact_name="wireshark/traffic.pcapng",
    )

    print("Wireshark upload complete.")

    # --------------------------------------------------
    # Upload INetSim artifacts recursively
    # --------------------------------------------------
    print("Uploading INetSim artifacts to MinIO...")

    inetsim_minio_runner.upload_directory(
        guest_directory_path=inetsim_output_dir,
        sample_id=SAMPLE_ID,
        sample_variant=SAMPLE_VARIANT,
        sha256=SHA256,
        directory_name="inetsim",
    )

    print("INetSim upload complete.")

    # --------------------------------------------------
    # Verify uploaded objects through MinIO aliases
    # --------------------------------------------------
    print("Verifying Wireshark upload in MinIO...")

    pcap_destination = (
        f"datapool-pcap/dynamic/"
        f"{SAMPLE_ID}/"
        f"{SAMPLE_VARIANT}/"
        f"{SHA256}/"
        f"wireshark/traffic.pcapng"
    )

    ubuntu_vm.run_bash(
        f'mc stat "{pcap_destination}"'
    )

    print("Verifying INetSim upload in MinIO...")

    inetsim_destination = (
        f"datapool-inetsim/dynamic/"
        f"{SAMPLE_ID}/"
        f"{SAMPLE_VARIANT}/"
        f"{SHA256}/"
        f"inetsim/"
    )

    ubuntu_vm.run_bash(
        f'mc ls --recursive "{inetsim_destination}"'
    )

    # --------------------------------------------------
    # Final result
    # --------------------------------------------------
    print()
    print("=== Ubuntu Dynamic Upload Test ===")
    print(f"sample_id: {SAMPLE_ID}")
    print(f"variant: {SAMPLE_VARIANT}")
    print(f"sha256: {SHA256}")
    print(f"dynamic_dir: {dynamic_dir}")
    print(f"pcap_output_path: {pcap_output_path}")
    print(f"inetsim_output_dir: {inetsim_output_dir}")
    print("wireshark_upload_complete: True")
    print("inetsim_upload_complete: True")


finally:
    # --------------------------------------------------
    # Best-effort service cleanup
    # --------------------------------------------------
    try:
        if inetsim_runner.is_running():
            inetsim_runner.stop()
    except Exception:
        pass

    try:
        if wireshark_runner.is_running(dynamic_dir):
            wireshark_runner.stop(dynamic_dir)
    except Exception:
        pass

    # --------------------------------------------------
    # Only stop VM if this script originally started it
    # --------------------------------------------------
    if not ubuntu_was_running:
        try:
            ubuntu_vm.stop()
        except RuntimeError:
            pass