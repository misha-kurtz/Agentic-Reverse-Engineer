# agentic-reverse-engineer/main.py
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

from controller.controller import AnalysisController

from runners.vmware import VMwareRunner
from runners.minio_dispatch import MinioDispatchRunner
from runners.remnux_dispatch import RemnuxDispatchRunner
from runners.pefile import PEFileRunner
from runners.minio_artifacts import MinioArtifactRunner
from runners.floss import FLOSSRunner
from runners.capa import CAPARunner
from runners.ghidra import GhidraRunner
from runners.windows_dispatch import WindowsDispatchRunner
from runners.ubuntu import UbuntuRunner
from runners.inetsim import INetSimRunner
from runners.wireshark import WiresharkRunner
from runners.noriben import NoribenRunner
from runners.regshot import RegshotRunner
from runners.sysmon import SysmonRunner
from runners.minio_dynamic import MinioDynamicRunner

from workflows.static_analysis import StaticAnalysisWorkflow
from workflows.detection import DetectionWorkflow
from workflows.dynamic_analysis import DynamicAnalysisWorkflow

SAMPLE_ID = "B001"

SAMPLES = {
    "original": "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59",
    "packed": "7141ef42cb8c213e2ee02cb2ef18e5bf8e862282ab236d39f4115199c16bf402",
    "encrypted": "c1d38e72ae55dc9232c962df041ef5371bf53cce1696867360ebcacd2d914109",
}


# --------------------------------------------------
# Resolve sample variant
# --------------------------------------------------

if len(sys.argv) != 2:
    raise SystemExit(
        "Usage: python main.py "
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

datapool_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server.vmx",
    guest_username="kurtz",
    password_env_var="DATAPOOL_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)


# --------------------------------------------------
# REMnux Linux Static Analysis VM
# --------------------------------------------------

remnux_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\REMnux Linux\REMnux Linux\REMnux Linux.vmx",
    guest_username="misha.kurtz",
    password_env_var="REMNUX_GUEST_PASSWORD",
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


datapool_was_running = datapool_vm.is_running()
remnux_was_running = remnux_vm.is_running()
ubuntu_was_running = ubuntu_vm.is_running()
windows_was_running = windows_vm.is_running()


try:
    datapool_vm.start()
    remnux_vm.start()
    ubuntu_vm.start()
    windows_vm.start(nogui=False)

    datapool_vm.wait_for_guest()
    remnux_vm.wait_for_guest()
    ubuntu_vm.wait_for_guest()
    windows_vm.wait_for_guest(
        shell="windows",
    )

    ghidra_runner = GhidraRunner(
        remnux_vm=remnux_vm,
        analyze_headless_path=PurePosixPath(
            "/opt/ghidra/support/analyzeHeadless"
        ),
        script_path=PurePosixPath(
            "/home/misha.kurtz/binary-eval/ghidra-scripts"
        ),
    )

    
    # --------------------------------------------------
    # Instantiate core runners
    # --------------------------------------------------

    minio_dispatch = MinioDispatchRunner(datapool_vm)
    minio_dispatch.wait_for_minio()

    remnux_dispatch = RemnuxDispatchRunner(remnux_vm)
    minio_artifact_runner = MinioArtifactRunner(remnux_vm)
    pefile_runner = PEFileRunner(remnux_vm)
    floss_runner = FLOSSRunner(remnux_vm)
    capa_runner = CAPARunner(remnux_vm)

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
    # Instantiate workflows
    # --------------------------------------------------

    static_analysis_workflow = StaticAnalysisWorkflow(
        pefile_runner=pefile_runner,
        floss_runner=floss_runner,
        capa_runner=capa_runner,
        ghidra_runner=ghidra_runner,
        minio_artifact_runner=minio_artifact_runner,
    )

    detection_workflow = DetectionWorkflow(
    remnux_vm=remnux_vm,
    )

    dynamic_analysis_workflow = DynamicAnalysisWorkflow(
        windows_vm=windows_vm,
        inetsim_runner=inetsim_runner,
        wireshark_runner=wireshark_runner,
        noriben_runner=noriben_runner,
        regshot_runner=regshot_runner,
        sysmon_runner=sysmon_runner,
        inetsim_minio_runner=inetsim_minio_runner,
        pcap_minio_runner=pcap_minio_runner,
        windows_minio_runner=windows_minio_runner,
    )

    # --------------------------------------------------
    # Instantiate controller
    # --------------------------------------------------
    controller = AnalysisController(
        minio_dispatch=minio_dispatch,
        remnux_dispatch=remnux_dispatch,
        windows_dispatch=windows_dispatch,
        ubuntu_runner=ubuntu_runner,
        static_analysis_workflow=static_analysis_workflow,
        detection_workflow=detection_workflow,
        dynamic_analysis_workflow=dynamic_analysis_workflow,
    )

    print("=== Selected Sample ===")
    print(f"sample_id: {SAMPLE_ID}")
    print(f"variant: {SAMPLE_VARIANT}")
    print(f"sha256: {SHA256}")
    print()

    # Execution flow:
    # prepare static sample
    # -> static analysis
    # -> detection
    # -> recovery policy
    # -> prepare dynamic sample
    # -> dynamic analysis

    state = controller.prepare_sample(
        sample_id=SAMPLE_ID,
        sha256=SHA256,
        sample_variant=SAMPLE_VARIANT,
        host_temp_url_path=Path(
            r"C:\Users\MK\AppData\Local\Temp\presigned_url.txt"
        ),
    )

    state = controller.run_static_analysis(
        state,
        binary_view="initial",
    )

    state = controller.run_detection(state)

    state = controller.apply_policy(state)

    state = controller.prepare_dynamic_sample(state)

    state = controller.run_dynamic_analysis(
        state,
        execution_seconds=60,
    )

    
    print(f"sample_id: {state.sample_id}")
    print(f"variant: {state.sample_variant}")
    print(f"sample_downloaded: {state.sample_downloaded}")
    print(f"sha256_verified: {state.sha256_verified}")

    print(f"pe_metadata_path: {state.pe_metadata_path}")
    print(f"pe_analysis_complete: {state.pe_analysis_complete}")
    print(f"pe_upload_complete: {state.pe_upload_complete}")

    print(f"floss_output_path: {state.floss_output_path}")
    print(f"floss_analysis_complete: {state.floss_analysis_complete}")
    print(f"floss_upload_complete: {state.floss_upload_complete}")

    print(f"capa_output_path: {state.capa_output_path}")
    print(f"capa_analysis_complete: {state.capa_analysis_complete}")
    print(f"capa_upload_complete: {state.capa_upload_complete}")

    print(f"ghidra_output_dir: {state.ghidra_output_dir}")
    print(f"ghidra_analysis_complete: {state.ghidra_analysis_complete}")
    print(f"ghidra_upload_complete: {state.ghidra_upload_complete}")

    print()
    print("=== Packing Detection ===")
    print(f"packing_detected: {state.packing_detected}")
    print(f"packing_family: {state.packing_family}")
    print(f"packing_confidence: {state.packing_confidence}")
    print("packing_indicators:")
    for indicator in state.packing_indicators:
        print(f"  - {indicator}")

    print()
    print("=== Encryption Detection ===")
    print(f"encrypted_payload_suspected: {state.encrypted_payload_suspected}")
    print(f"encryption_family: {state.encryption_family}")
    print(f"encryption_confidence: {state.encryption_confidence}")
    print("encryption_indicators:")
    for indicator in state.encryption_indicators:
        print(f"  - {indicator}")

    print()
    print("=== Recovery Policy ===")
    print(f"recovery_policy: {state.recovery_policy}")
    print(f"recovery_required: {state.recovery_required}")
    print(f"recovery_strategy: {state.recovery_strategy}")

    print()
    print("=== Dynamic Analysis ===")

    print(f"dynamic_sample_downloaded: {state.dynamic_sample_downloaded}")
    print(f"dynamic_sha256_verified: {state.dynamic_sha256_verified}")
    print(f"windows_sample_path: {state.windows_sample_path}")
    print(f"ubuntu_dynamic_dir: {state.ubuntu_dynamic_dir}")
    print(f"windows_dynamic_dir: {state.windows_dynamic_dir}")
    print(f"sample_executed: {state.sample_executed}")
    print(f"pcap_output_path: {state.pcap_output_path}")
    print(f"inetsim_output_dir: {state.inetsim_output_dir}")
    print(f"noriben_output_dir: {state.noriben_output_dir}")
    print(f"regshot_output_path: {state.regshot_output_path}")
    print(f"sysmon_output_path: {state.sysmon_output_path}")
    print(f"wireshark_upload_complete: {state.wireshark_upload_complete}")
    print(f"inetsim_upload_complete: {state.inetsim_upload_complete}")
    print(f"noriben_upload_complete: {state.noriben_upload_complete}")
    print(f"regshot_upload_complete: {state.regshot_upload_complete}")
    print(f"sysmon_upload_complete: {state.sysmon_upload_complete}")

finally:
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

    if not remnux_was_running:
        try:
            remnux_vm.stop()
        except RuntimeError:
            pass

    if not datapool_was_running:
        try:
            datapool_vm.stop()
        except RuntimeError:
            pass