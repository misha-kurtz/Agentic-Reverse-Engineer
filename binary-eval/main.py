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


SHA256 = (
    "96a281d5f33040f463c4e20bf33835ddeb391ddc50627d863e214d772c1b8a59"
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

ghidra_runner = GhidraRunner(
    remnux_vm=remnux_vm,

    # Replace this with the actual path returned by find
    analyze_headless_path=PurePosixPath(
        "/opt/ghidra/support/analyzeHeadless"
    ),

    script_path=PurePosixPath(
        "/home/misha.kurtz/binary-eval/ghidra-scripts"
    ),
)

minio_dispatch = MinioDispatchRunner(datapool_vm)
remnux_dispatch = RemnuxDispatchRunner(remnux_vm)
pefile_runner = PEFileRunner(remnux_vm)
minio_artifact_runner = MinioArtifactRunner(remnux_vm)
floss_runner = FLOSSRunner(remnux_vm)
capa_runner = CAPARunner(remnux_vm)

controller = AnalysisController(
    minio_dispatch=minio_dispatch,
    remnux_dispatch=remnux_dispatch,
    pefile_runner=pefile_runner,
    floss_runner=floss_runner,
    capa_runner=capa_runner,
    ghidra_runner=ghidra_runner,
    minio_artifact_runner=minio_artifact_runner,
)

state = controller.prepare_sample(
    sample_id="B001",
    sha256=SHA256,
    sample_variant="original",
    host_temp_url_path=Path(
        r"C:\Users\MK\AppData\Local\Temp\presigned_url.txt"
    ),
)

state = controller.run_pe_analysis(state)
state = controller.run_floss_analysis(state)
state = controller.run_capa_analysis(state)
state = controller.run_ghidra_analysis(state)

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