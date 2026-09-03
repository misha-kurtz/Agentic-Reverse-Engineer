# binary-eval/workflows/static_analysis.py

from controller.state import AnalysisState


class StaticAnalysisWorkflow:
    '''
    Runs the complete static-analysis workflow for a sample and uploads 
    resulting artifacts from REMnux VM to MinIO S3 bucket on Debian datapool.

    The workflow coordinates the individual static-analysis operations:
        1. PE metadata extraction
        2. FLOSS string analysis
        3. capa capability analysis
        4. Ghidra analysis

    The individual analysis operations remain implemented by the controller
    and runners. This class is responsible only for their execution order.
    '''

    def __init__(
        self,
        pefile_runner,
        floss_runner,
        capa_runner,
        ghidra_runner,
        minio_artifact_runner,
    ):
        self.pefile_runner = pefile_runner
        self.floss_runner = floss_runner
        self.capa_runner = capa_runner
        self.ghidra_runner = ghidra_runner
        self.minio_artifact_runner = minio_artifact_runner

    # ----------------------------------------------------------------
    # Invoke the static analysis tools for the current 
    # malware sample (PEfile, FLOSS, capa Ghidra)
    # ----------------------------------------------------------------
    def run(
        self,
        state: AnalysisState,
        binary_view: str = "initial",
    ) -> AnalysisState:

        if binary_view not in {"initial", "recovered"}:
            raise ValueError(
                f"Unsupported binary_view: {binary_view}"
            )

        if binary_view == "recovered":
            raise NotImplementedError(
                "Recovered static analysis has not been implemented yet"
            )

        state = self.run_pe_analysis(state)
        state = self.run_floss_analysis(state)
        state = self.run_capa_analysis(state)
        state = self.run_ghidra_analysis(state)

        return state

    # ----------------------------------------------------------------
    # Run PE metadata extraction for current malware sample
    # Upload JSON artifact to MinIO S3 bucket on Debian Datapool
    # ----------------------------------------------------------------
    def run_pe_analysis(
        self,
        state: AnalysisState,
    ) -> AnalysisState:

        pe_metadata_path = (
            state.guest_static_dir / "pe.json"
        )

        self.pefile_runner.analyze(
            guest_sample_path=state.guest_sample_path,
            guest_output_path=pe_metadata_path,
        )

        state.pe_metadata_path = pe_metadata_path
        state.pe_analysis_complete = True

        self.minio_artifact_runner.upload(
            guest_artifact_path=pe_metadata_path,
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
            artifact_name="pe.json",
        )

        state.pe_upload_complete = True

        return state

    # ------------------------------------------------------------------
    # Run FLOSS string extraction for current malware sample and upload  
    # JSON artifact from REMnux VM to MinIO S3 bucket on Debian Datapool
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Run CAPA capability analysis for current malware sample and upload 
    # JSON artifact from REMnux VM to MinIO S3 bucket on Debian Datapool
    # ------------------------------------------------------------------
    def run_capa_analysis(
        self,
        state: AnalysisState,
    ) -> AnalysisState:
        
        capa_output_path = (
            state.guest_static_dir / "capa.json"
        )

        self.capa_runner.analyze(
            guest_sample_path=state.guest_sample_path,
            guest_output_path=capa_output_path,
        )

        state.capa_output_path = capa_output_path
        state.capa_analysis_complete = True

        self.minio_artifact_runner.upload(
            guest_artifact_path=capa_output_path,
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
            artifact_name="capa.json",
        )

        state.capa_upload_complete = True

        return state

    # ------------------------------------------------------------------
    #  Run Ghidra for current malware sample and upload directory of 
    #  artifacts from REMnux VM to MinIO S3 bucket on Debian Datapool
    # (decompiled code, assembly, CFGs, callgraph, imports, etc.)
    # ------------------------------------------------------------------
    def run_ghidra_analysis(
        self,
        state: AnalysisState,
    ) -> AnalysisState:

        ghidra_output_dir = (
            state.guest_static_dir / "ghidra"
        )

        self.ghidra_runner.analyze(
            guest_sample_path=state.guest_sample_path,
            guest_output_dir=ghidra_output_dir,
        )

        state.ghidra_output_dir = ghidra_output_dir
        state.ghidra_analysis_complete = True

        self.minio_artifact_runner.upload_directory(
            guest_directory_path=ghidra_output_dir,
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
            directory_name="ghidra",
        )

        state.ghidra_upload_complete = True

        return state

    # ------------------------------------------------------------------
    # Clean static analysis artifacts from MinIO S3 buckets  
    # on Debian Datapool for any previous run of sample
    # ------------------------------------------------------------------
    def clean_artifacts(
        self,
        sample_id: str,
        sample_variant: str,
        sha256: str,
    ) -> None:

        self.minio_artifact_runner.clean_static_prefix(
            sample_id=sample_id,
            sample_variant=sample_variant,
            sha256=sha256,
        )