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


SHA256 = (
    "c1d38e72ae55dc9232c962df041ef5371bf53cce1696867360ebcacd2d914109"
)


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

datapool_was_running = datapool_vm.is_running()
remnux_was_running = remnux_vm.is_running()

#success = False

try:
    datapool_vm.start()
    remnux_vm.start()

    #datapool_vm.start(nogui=False)
    #remnux_vm.start()

    datapool_vm.wait_for_guest()
    remnux_vm.wait_for_guest()

    ghidra_runner = GhidraRunner(
        remnux_vm=remnux_vm,
        analyze_headless_path=PurePosixPath(
            "/opt/ghidra/support/analyzeHeadless"
        ),
        script_path=PurePosixPath(
            "/home/misha.kurtz/binary-eval/ghidra-scripts"
        ),
    )

    minio_dispatch = MinioDispatchRunner(datapool_vm)
    remnux_dispatch = RemnuxDispatchRunner(remnux_vm)
    minio_artifact_runner = MinioArtifactRunner(remnux_vm)
    pefile_runner = PEFileRunner(remnux_vm)
    floss_runner = FLOSSRunner(remnux_vm)
    capa_runner = CAPARunner(remnux_vm)

    minio_dispatch.wait_for_minio()

    static_analysis_workflow = StaticAnalysisWorkflow(
        pefile_runner=pefile_runner,
        floss_runner=floss_runner,
        capa_runner=capa_runner,
        ghidra_runner=ghidra_runner,
        minio_artifact_runner=minio_artifact_runner,
    )

    controller = AnalysisController(
        minio_dispatch=minio_dispatch,
        remnux_dispatch=remnux_dispatch,
        static_analysis_workflow=static_analysis_workflow,
    )


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

    #success = True
    
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

# finally:
#     if success:
#         if not remnux_was_running:
#             remnux_vm.stop()
#
#         if not datapool_was_running:
#             datapool_vm.stop()

finally:
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