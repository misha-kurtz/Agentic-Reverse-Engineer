# binary-eval/workflows/dynamic_analysis.py

from controller.state import AnalysisState


class DynamicAnalysisWorkflow:
    def __init__(
        self,
        noriben_runner,
        regshot_runner,
        sysmon_runner,
        minio_artifact_runner,
    ):
        self.noriben_runner = noriben_runner
        self.regshot_runner = regshot_runner
        self.sysmon_runner = sysmon_runner
        self.minio_artifact_runner = minio_artifact_runner

    def clean_artifacts(
        self,
        sample_id: str,
        sample_variant: str,
        sha256: str,
    ) -> None:

        self.minio_artifact_runner.clean_dynamic_prefix(
            sample_id=sample_id,
            sample_variant=sample_variant,
            sha256=sha256,
        )