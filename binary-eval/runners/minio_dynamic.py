# binary-eval/runners/minio_dynamic.py

from pathlib import PurePosixPath

from runners.vmware import VMwareRunner


class MinioDynamicRunner:
    def __init__(
        self,
        vm: VMwareRunner,
        alias: str,
    ):
        self.vm = vm
        self.alias = alias

    def upload(
        self,
        guest_artifact_path: PurePosixPath,
        sample_id: str,
        sample_variant: str,
        sha256: str,
        artifact_name: str,
    ) -> None:

        destination = (
            f"{self.alias}/dynamic/"
            f"{sample_id}/"
            f"{sample_variant}/"
            f"{sha256}/"
            f"{artifact_name}"
        )

        self.vm.run_bash(
            f'mc cp "{guest_artifact_path}" "{destination}"'
        )

    def upload_directory(
        self,
        guest_directory_path: PurePosixPath,
        sample_id: str,
        sample_variant: str,
        sha256: str,
        directory_name: str,
    ) -> None:

        destination = (
            f"{self.alias}/dynamic/"
            f"{sample_id}/"
            f"{sample_variant}/"
            f"{sha256}/"
            f"{directory_name}/"
        )

        self.vm.run_bash(
            f'mc cp --recursive '
            f'"{guest_directory_path}/" '
            f'"{destination}"'
        )

    def clean_directory_prefix(
        self,
        sample_id: str,
        sample_variant: str,
        sha256: str,
        directory_name: str,
    ) -> None:

        destination = (
            f"{self.alias}/dynamic/"
            f"{sample_id}/"
            f"{sample_variant}/"
            f"{sha256}/"
            f"{directory_name}/"
        )

        self.vm.run_bash(
            f'mc rm --recursive --force --quiet "{destination}"'
        )