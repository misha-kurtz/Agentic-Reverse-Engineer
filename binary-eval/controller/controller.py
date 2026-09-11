# binary-eval/controller/controller.py

from pathlib import Path, PurePosixPath, PureWindowsPath

from controller.policy import choose_recovery_policy
from controller.decisions import RecoveryPolicy
from controller.state import AnalysisState

from runners.minio_dispatch import MinioDispatchRunner
from runners.remnux_dispatch import RemnuxDispatchRunner
from runners.windows_dispatch import WindowsDispatchRunner
from runners.ubuntu import UbuntuRunner

from workflows.static_analysis import StaticAnalysisWorkflow
from workflows.dynamic_analysis import DynamicAnalysisWorkflow




class AnalysisController:
    def __init__(
        self,
        minio_dispatch: MinioDispatchRunner,
        remnux_dispatch: RemnuxDispatchRunner,
        windows_dispatch: WindowsDispatchRunner,
        ubuntu_runner: UbuntuRunner,
        static_analysis_workflow: StaticAnalysisWorkflow,
        detection_workflow,
        dynamic_analysis_workflow: DynamicAnalysisWorkflow | None = None,
    ):
        self.minio_dispatch = minio_dispatch
        self.remnux_dispatch = remnux_dispatch
        self.windows_dispatch = windows_dispatch
        self.ubuntu_runner = ubuntu_runner

        self.static_analysis_workflow = static_analysis_workflow
        self.detection_workflow = detection_workflow
        self.dynamic_analysis_workflow = dynamic_analysis_workflow

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

    # ------------------------------------------------------
    # Invoke static analysis for current malware sample.
    # Return updated sample analysis state.
    # ------------------------------------------------------
    def run_static_analysis(
        self,
        state: AnalysisState,
        binary_view: str = "initial",
    ) -> AnalysisState:
        
        return self.static_analysis_workflow.run(
            state,
            binary_view=binary_view,
        )


    # -----------------------------------------------------
    # Invoke detection method for current malware sample.
    # Determines if sample is packed or encrypted and
    # updates sample analysis state.
    # -----------------------------------------------------
    def run_detection(
        self,
        state: AnalysisState,
    ) -> AnalysisState:

        return self.detection_workflow.run(state)

    # --------------------------------------------------------
    # Apply recovery policy for current malware sample.
    # Protected samples may require dynamic recovery:
    #  - packing -> recover payload via automated unpacking
    #  - encryption-> recover payload via automated decryption
    #  - no obfuscation -> no recovery workflow is required.
    # ---------------------------------------------------------
    def apply_policy(
        self,
        state: AnalysisState,
    ) -> AnalysisState:

        policy = choose_recovery_policy(state)

        state.recovery_policy = policy.value

        if policy is RecoveryPolicy.AUTOMATED_UNPACKING:
            state.recovery_required = True
            state.recovery_strategy = "dynamic"

        elif policy is RecoveryPolicy.AUTOMATED_DECRYPTION:
            state.recovery_required = True
            state.recovery_strategy = "dynamic"

        else:
            state.recovery_required = False
            state.recovery_strategy = None

        return state

    
    # --------------------------------------------------
    # Download malware sample from Debian MinIO server to 
    # Windows VM and verify against expected SHA256 hash.
    # --------------------------------------------------
    def prepare_dynamic_sample(
        self,
        state: AnalysisState,
    ) -> AnalysisState:

        if state.presigned_url is None:
            raise RuntimeError(
                "Presigned sample URL is not available"
            )

        state.windows_sample_path = PureWindowsPath(
            rf"C:\binary-eval\work\{state.sample_id}"
            rf"\{state.sample_variant}\{state.sha256}"
            rf"\sample.exe"
        )

        state.windows_dynamic_dir = PureWindowsPath(
            rf"C:\binary-eval\work\{state.sample_id}"
            rf"\{state.sample_variant}\{state.sha256}"
            rf"\dynamic"
        )

        # Clean previous Windows workspace
        self.windows_dispatch.clean_sample_workspace(
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
        )

        # Clean previous Ubuntu workspace
        self.ubuntu_runner.clean_dynamic_workspace(
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
        )

        # Clean previous MinIO dynamic artifacts
        self.dynamic_analysis_workflow.clean_artifacts(
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
        )

        # Prepare Ubuntu workspace
        state.ubuntu_dynamic_dir = (
            self.ubuntu_runner.prepare_dynamic_workspace(
                sample_id=state.sample_id,
                sample_variant=state.sample_variant,
                sha256=state.sha256,
            )
        )

        # Download sample to Windows
        self.windows_dispatch.download_and_verify(
            presigned_url=state.presigned_url,
            expected_sha256=state.sha256,
            guest_sample_path=state.windows_sample_path,
        )

        state.dynamic_sample_downloaded = True
        state.dynamic_sha256_verified = True

        return state

    # --------------------------------------------------
    # Run baseline dynamic analysis for every sample.
    # --------------------------------------------------
    def run_dynamic_analysis(
        self,
        state: AnalysisState,
        execution_seconds: int = 60,
    ) -> AnalysisState:

        if self.dynamic_analysis_workflow is None:
            raise RuntimeError(
                "Dynamic analysis workflow has not been configured"
            )

        return self.dynamic_analysis_workflow.run(
            state,
            execution_seconds=execution_seconds,
        )