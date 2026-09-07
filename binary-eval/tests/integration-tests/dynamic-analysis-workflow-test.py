from pathlib import Path, PurePosixPath

from controller.controller import AnalysisController

from runners.vmware import VMwareRunner
from runners.minio_dispatch import MinioDispatchRunner
from runners.remnux_dispatch import RemnuxDispatchRunner
from runners.pefile import PEFileRunner
from runners.minio_artifacts import MinioArtifactRunner
from runners.floss import FLOSSRunner
from runners.capa import CAPARunner
from runners.ghidra import GhidraRunner

from workflows.static_analysis import StaticAnalysisWorkflow
from workflows.detection import DetectionWorkflow

# Change sample_variant to match SHA256 hash of sample
SHA256 = (
    "c1d38e72ae55dc9232c962df041ef5371bf53cce1696867360ebcacd2d914109"
)


'''

SHA256 = (
    "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59"
)
SHA256 = (
    "7141ef42cb8c213e2ee02cb2ef18e5bf8e862282ab236d39f4115199c16bf402"
)
'''



datapool_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server.vmx",
    guest_username="kurtz",
    password_env_var="DATAPOOL_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

remnux_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\REMnux Linux\REMnux Linux\REMnux Linux.vmx",
    guest_username="misha.kurtz",
    password_env_var="REMNUX_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

windows_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Windows 11 x64\Windows 11 x64\Windows 11 x64.vmx",
    guest_username="misha.kurtz",
    password_env_var="WINDOWS_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

ubuntu_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway\Ubuntu 64-bit Inetsim-Gateway.vmx",
    guest_username="kurtz",
    password_env_var="UBUNTU_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

datapool_was_running = datapool_vm.is_running()
remnux_was_running = remnux_vm.is_running()
windows_was_running = windows_vm.is_running()
ubuntu_was_running = ubuntu_vm.is_running()

state = None

try:
    # --------------------------------------------------
    # Start datapool once and keep it running
    # --------------------------------------------------

    datapool_vm.start()
    datapool_vm.wait_for_guest(shell="bash")

    minio_dispatch = MinioDispatchRunner(datapool_vm)
    minio_dispatch.wait_for_minio()

    # ==================================================
    # Static phase
    # ==================================================

    try:
        remnux_vm.start()
        remnux_vm.wait_for_guest(shell="bash")

        remnux_dispatch = RemnuxDispatchRunner(remnux_vm)
        minio_artifact_runner = MinioArtifactRunner(remnux_vm)
        pefile_runner = PEFileRunner(remnux_vm)
        floss_runner = FLOSSRunner(remnux_vm)
        capa_runner = CAPARunner(remnux_vm)

        ghidra_runner = GhidraRunner(
            remnux_vm=remnux_vm,
            analyze_headless_path=PurePosixPath(
                "/opt/ghidra/support/analyzeHeadless"
            ),
            script_path=PurePosixPath(
                "/home/misha.kurtz/binary-eval/ghidra-scripts"
            ),
        )

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

        controller = AnalysisController(
            minio_dispatch=minio_dispatch,
            remnux_dispatch=remnux_dispatch,
            static_analysis_workflow=static_analysis_workflow,
            detection_workflow=detection_workflow,
            dynamic_analysis_workflow=None,  # Placeholder for dynamic analysis workflow
        )

        # Execution flow: prepare sample -> run static analysis -> run detection -> apply policy
        state = controller.prepare_sample(
            sample_id="B001",
            sha256=SHA256,
            sample_variant="encrypted",
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

    finally:
        if not remnux_was_running:
            try:
                remnux_vm.stop()
            except RuntimeError:
                pass

    # ==================================================
    # Dynamic phase
    # ==================================================

    if state is None:
        raise RuntimeError(
            "Static phase did not produce an AnalysisState"
        )

    try:
        windows_vm.start()
        ubuntu_vm.start()

        windows_vm.wait_for_guest(shell="windows")
        ubuntu_vm.wait_for_guest(shell="bash")

        dynamic_presigned_url = (
            minio_dispatch.generate_presigned_url(
                sample_id=state.sample_id,
                sha256=state.sha256,
                sample_variant=state.sample_variant,
                host_temp_path=Path(
                    r"C:\Users\MK\AppData\Local\Temp\presigned_url.txt"
                ),
            )
        )

        state = controller.run_dynamic_analysis(
            state=state,
            presigned_url=dynamic_presigned_url,
            execution_seconds=60,
        )

        #if state.recovery_required:
            #state = controller.run_recovery(state)

    finally:
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

finally:
    if not datapool_was_running:
        try:
            datapool_vm.stop()
        except RuntimeError:
            pass