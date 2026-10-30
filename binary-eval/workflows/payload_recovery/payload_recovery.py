
# binary-eval/workflows/payload_recovery/payload_recovery.py

from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
import json

from runners.recovery_dispatch import RecoveryDispatchRunner
from runners.minio_dispatch import MinioDispatchRunner
from runners.windows_dispatch import WindowsDispatchRunner

'''
Uniform Interface for Deterministic Payload Recovery Workflows

Purpose:
    Coordinate deterministic payload recovery using the recovery policy
    previously selected by AnalysisController.

Responsibilities:
    1. Receive the protected executable's existing Windows path.
    2. Receive the recovery policy selected by AnalysisController.
    3. Invoke RecoveryDispatchRunner to package and deploy recovery scripts.
    4. Invoke RecoveryDispatchRunner to execute the requested recovery procedure.
    5. Retrieve and normalize recovery results into PayloadRecoveryResult.

'''


@dataclass(frozen=True)
class PayloadRecoveryResult:
    recovery_method: str
    protected_sha256: str
    recovered_sha256: str

    protected_path: PureWindowsPath
    recovered_path: PureWindowsPath

    oep_rva: int
    iat_rva: int
    iat_size: int

    iat_valid_thunks: int
    iat_invalid_thunks: int

    recovery_successful: bool
    recovered_upload_complete: bool


class PayloadRecoveryWorkflow:
    def __init__(
        self,
        recovery_dispatch: RecoveryDispatchRunner,
        minio_dispatch: MinioDispatchRunner,
        windows_dispatch: WindowsDispatchRunner,
    ):
        self.recovery_dispatch = recovery_dispatch
        self.minio_dispatch = minio_dispatch
        self.windows_dispatch = windows_dispatch

    def run(
        self,
        recovery_method: str,
        protected_sha256: str,
        guest_sample_path: PureWindowsPath,
        repository_root: Path,
        host_archive_path: Path,
        guest_archive_path: PureWindowsPath,
        guest_code_dir: PureWindowsPath,
        guest_output_dir: PureWindowsPath,
        host_result_path: Path,
        cdb_path: PureWindowsPath,
        sample_id: str,
        sample_variant: str,
        host_temp_url_path: Path,
    ) -> PayloadRecoveryResult:
        '''
        Coordinate deterministic payload recovery using the controller-selected method.
        '''

        if recovery_method not in ("AUTOMATED_UNPACKING", "AUTOMATED_DECRYPTION"):
            raise ValueError(f"Unsupported recovery method: {recovery_method}")

        # Package the deterministic recovery modules.
        archive_path = self.recovery_dispatch.package(repository_root, host_archive_path)

        # Deploy the recovery modules inside Windows.
        self.recovery_dispatch.deploy(archive_path, guest_archive_path, guest_code_dir)

        # Execute the recovery procedure requested by AnalysisController.
        self.recovery_dispatch.execute(
            recovery_method,
            guest_sample_path,
            guest_output_dir,
            guest_code_dir,
            cdb_path,
        )

        # Retrieve the recovery metadata.
        guest_result_path = guest_output_dir / "recovery_result.json"
        self.recovery_dispatch.retrieve_result(guest_result_path, host_result_path)

        # Parse the recovery metadata.
        with host_result_path.open("r", encoding="utf-8") as file:
            result_data = json.load(file)

        # Validate recovery status.
        if not result_data.get("recovery_successful", False):
            raise RuntimeError(f"Payload recovery failed: {result_data.get('error', 'Unknown error')}")

        # Verify the protected executable identity.
        if result_data["protected_sha256"].lower() != protected_sha256.lower():
            raise ValueError("Protected executable SHA-256 mismatch in recovery results")

        # Verify the requested recovery method.
        if result_data["recovery_method"] != recovery_method:
            raise ValueError("Recovery method mismatch in recovery results")

        # Verify the protected executable path.
        if PureWindowsPath(result_data["protected_path"]) != guest_sample_path:
            raise ValueError("Protected executable path mismatch in recovery results")

        # --------------------------------------------------
        # Upload recovered payload to MinIO
        # --------------------------------------------------

        recovered_path = PureWindowsPath(result_data["recovered_path"])
        recovered_sha256 = result_data["recovered_sha256"]

        # Generate a fresh presigned PUT URL
        presigned_put_url = self.minio_dispatch.generate_presigned_url_put(
            sample_id=sample_id,
            recovered_sha256=recovered_sha256,
            sample_variant=sample_variant,
            host_temp_path=host_temp_url_path,
        )

        # Verify recovered executable and upload to MinIO
        self.windows_dispatch.verify_and_upload(
            presigned_url=presigned_put_url,
            expected_sha256=recovered_sha256,
            guest_recovered_path=recovered_path,
        )

        print("[recovery] Recovered payload uploaded successfully")

        # Normalize the recovery metadata.
        return PayloadRecoveryResult(
            recovery_method=result_data["recovery_method"],
            protected_sha256=result_data["protected_sha256"],
            recovered_sha256=result_data["recovered_sha256"],
            protected_path=PureWindowsPath(result_data["protected_path"]),
            recovered_path=PureWindowsPath(result_data["recovered_path"]),
            oep_rva=int(result_data["oep_rva"], 16),
            iat_rva=int(result_data["iat_rva"], 16),
            iat_size=int(result_data["iat_size"], 16),
            iat_valid_thunks=result_data["iat_valid_thunks"],
            iat_invalid_thunks=result_data["iat_invalid_thunks"],
            recovery_successful=result_data["recovery_successful"],
            recovered_upload_complete=True,
        )