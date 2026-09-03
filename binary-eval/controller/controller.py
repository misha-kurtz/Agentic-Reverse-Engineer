# binary-eval/controller/controller.py

from pathlib import Path, PurePosixPath

from controller.state import AnalysisState
from runners.minio_dispatch import MinioDispatchRunner
from runners.remnux_dispatch import RemnuxDispatchRunner
from workflows.static_analysis import StaticAnalysisWorkflow


class AnalysisController:
    def __init__(
        self,
        minio_dispatch: MinioDispatchRunner,
        remnux_dispatch: RemnuxDispatchRunner,
        static_analysis_workflow: StaticAnalysisWorkflow,
    ):
        self.minio_dispatch = minio_dispatch
        self.remnux_dispatch = remnux_dispatch
        self.static_analysis_workflow = static_analysis_workflow

    # --------------------------------------------------
    # Download malware sample from Debian MinIO server to 
    # REMnux VM and verify against expected SHA256 hash.
    # --------------------------------------------------
    def prepare_sample(
        self,
        sample_id: str,
        sha256: str,
        sample_variant: str,
        host_temp_url_path: Path,
    ) -> AnalysisState:

        # Sample path on REMnux VM
        guest_sample_path = PurePosixPath(
            f"/home/misha.kurtz/binary-eval/work/"
            f"{sample_id}/{sample_variant}/{sha256}/sample.bin"
        )

        # Static artifact output directory on REMnux VM
        guest_static_dir = PurePosixPath(
            f"/home/misha.kurtz/binary-eval/work/"
            f"{sample_id}/{sample_variant}/{sha256}/static"
        )

        # Instantiate AnalysisState object to track 
        # artifact generation and analysis progress
        state = AnalysisState(
            sample_id=sample_id,
            sha256=sha256,
            sample_variant=sample_variant,
            guest_sample_path=guest_sample_path,
            guest_static_dir=guest_static_dir,
        )

        # Remove artifacts from REMnux for any previous run of sample 
        self.remnux_dispatch.clean_sample_workspace(
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
        )

        # Clean static analysis artifacts from MinIO S3 buckets 
        # on Debian Datapool for any previous run of sample
        self.static_analysis_workflow.clean_artifacts(
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
        )

        # Generate presigned URL for sample download from MinIO S3 bucket
        state.presigned_url = (
            self.minio_dispatch.generate_presigned_url(
                sample_id=state.sample_id,
                sha256=state.sha256,
                sample_variant=state.sample_variant,
                host_temp_path=host_temp_url_path,
            )
        )

        # Download sample via presigned URL to REMnux VM and verify SHA-256 hash
        self.remnux_dispatch.download_and_verify(
            presigned_url=state.presigned_url,
            expected_sha256=state.sha256,
            guest_sample_path=state.guest_sample_path,
        )

        state.sample_downloaded = True
        state.sha256_verified = True

        return state

    # --------------------------------------------------
    # Invoke static analysis for current malware sample.
    # Return updated sample analysis state.
    # --------------------------------------------------
    def run_static_analysis(
        self,
        state: AnalysisState,
        binary_view: str = "initial",
    ) -> AnalysisState:
        
        return self.static_analysis_workflow.run(
            state,
            binary_view=binary_view,
        )