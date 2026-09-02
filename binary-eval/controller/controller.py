from pathlib import Path, PurePosixPath

from controller.state import AnalysisState
from runners.minio_dispatch import MinioDispatchRunner
from runners.remnux_dispatch import RemnuxDispatchRunner
from runners.pefile import PEFileRunner
from runners.minio_artifacts import MinioArtifactRunner
from runners.floss import FLOSSRunner
from runners.capa import CAPARunner
from runners.ghidra import GhidraRunner


class AnalysisController:
    def __init__(
        self,
        minio_dispatch: MinioDispatchRunner,
        remnux_dispatch: RemnuxDispatchRunner,
        pefile_runner: PEFileRunner,
        floss_runner: FLOSSRunner,
        capa_runner: CAPARunner,
        ghidra_runner: GhidraRunner,
        minio_artifact_runner: MinioArtifactRunner,
    ):
        self.minio_dispatch = minio_dispatch
        self.remnux_dispatch = remnux_dispatch
        self.pefile_runner = pefile_runner
        self.floss_runner = floss_runner
        self.capa_runner = capa_runner
        self.ghidra_runner = ghidra_runner
        self.minio_artifact_runner = minio_artifact_runner


    def prepare_sample(
        self,
        sample_id: str,
        sha256: str,
        sample_variant: str,
        host_temp_url_path: Path,
    ) -> AnalysisState:

        guest_sample_path = PurePosixPath(
            f"/home/misha.kurtz/binary-eval/work/"
            f"{sample_id}/{sample_variant}/{sha256}/sample.bin"
        )

        guest_static_dir = PurePosixPath(
            f"/home/misha.kurtz/binary-eval/work/"
            f"{sample_id}/{sample_variant}/{sha256}/static"
        )

        state = AnalysisState(
            sample_id=sample_id,
            sha256=sha256,
            sample_variant=sample_variant,
            guest_sample_path=guest_sample_path,
            guest_static_dir=guest_static_dir,
        )

        # 1. Generate presigned URL
        state.presigned_url = (
            self.minio_dispatch.generate_presigned_url(
                sample_id=state.sample_id,
                sha256=state.sha256,
                sample_variant=state.sample_variant,
                host_temp_path=host_temp_url_path,
            )
        )

        # 2. Download sample directly to REMnux and verify SHA-256
        self.remnux_dispatch.download_and_verify(
            presigned_url=state.presigned_url,
            expected_sha256=state.sha256,
            guest_sample_path=state.guest_sample_path,
        )

        state.sample_downloaded = True
        state.sha256_verified = True

        return state

    def run_pe_analysis(
        self,
        state: AnalysisState,
    ) -> AnalysisState:

        pe_metadata_path = (
            state.guest_static_dir / "pe.json"
        )

        # Generate pe.json on REMnux
        self.pefile_runner.analyze(
            guest_sample_path=state.guest_sample_path,
            guest_output_path=pe_metadata_path,
        )

        state.pe_metadata_path = pe_metadata_path
        state.pe_analysis_complete = True

        # Upload pe.json directly from REMnux to MinIO
        self.minio_artifact_runner.upload(
            guest_artifact_path=pe_metadata_path,
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
            artifact_name="pe.json",
        )

        state.pe_upload_complete = True

        return state


    def run_floss_analysis(
        self,
        state: AnalysisState,
    ) -> AnalysisState:

        floss_output_path = (
            state.guest_static_dir / "floss.json"
        )

        self.floss_runner.analyze(
            guest_sample_path=state.guest_sample_path,
            guest_output_path=floss_output_path,
        )

        state.floss_output_path = floss_output_path
        state.floss_analysis_complete = True

        self.minio_artifact_runner.upload(
            guest_artifact_path=floss_output_path,
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
            artifact_name="floss.json",
        )

        state.floss_upload_complete = True

        return state

    def run_capa_analysis(
        self,
        state: AnalysisState,
    ) -> AnalysisState:

        capa_output_path = (
            state.guest_static_dir / "capa.json"
        )

        # Generate capa.json on REMnux
        self.capa_runner.analyze(
            guest_sample_path=state.guest_sample_path,
            guest_output_path=capa_output_path,
        )

        state.capa_output_path = capa_output_path
        state.capa_analysis_complete = True

        # Upload capa.json directly from REMnux to MinIO
        self.minio_artifact_runner.upload(
            guest_artifact_path=capa_output_path,
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
            artifact_name="capa.json",
        )

        state.capa_upload_complete = True

        return state

    def run_ghidra_analysis(
        self,
        state: AnalysisState,
    ) -> AnalysisState:

        ghidra_output_dir = (
            state.guest_static_dir / "ghidra"
        )

        # Run Ghidra headless analysis on REMnux
        self.ghidra_runner.analyze(
            guest_sample_path=state.guest_sample_path,
            guest_output_dir=ghidra_output_dir,
        )

        state.ghidra_output_dir = ghidra_output_dir
        state.ghidra_analysis_complete = True

        # Upload entire Ghidra artifact directory
        # directly from REMnux to MinIO
        self.minio_artifact_runner.upload_directory(
            guest_directory_path=ghidra_output_dir,
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
            directory_name="ghidra",
        )

        state.ghidra_upload_complete = True

        return state