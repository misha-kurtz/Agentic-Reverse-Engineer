from pathlib import PurePosixPath

from runners.vmware import VMwareRunner


class MinioArtifactRunner:
    def __init__(self, remnux_vm: VMwareRunner):
        self.remnux_vm = remnux_vm

    def upload(
        self,
        guest_artifact_path: PurePosixPath,
        sample_id: str,
        sample_variant: str,
        sha256: str,
        artifact_name: str,
    ) -> None:

        destination = (
            f"datapool/static/"
            f"{sample_id}/"
            f"{sample_variant}/"
            f"{sha256}/"
            f"{artifact_name}"
        )

        command = (
            f'mc cp "{guest_artifact_path}" "{destination}"'
        )

        self.remnux_vm.run_bash(command)

    def upload_directory(
        self,
        guest_directory_path: PurePosixPath,
        sample_id: str,
        sample_variant: str,
        sha256: str,
        directory_name: str,
    ) -> None:

        destination = (
            f"datapool/static/"
            f"{sample_id}/"
            f"{sample_variant}/"
            f"{sha256}/"
            f"{directory_name}/"
        )

        command = (
            f'mc cp --recursive '
            f'"{guest_directory_path}/" '
            f'"{destination}"'
        )

        self.remnux_vm.run_bash(command)

    def clean_static_prefix(
        self,
        sample_id: str,
        sample_variant: str,
        sha256: str,
    ) -> None:

        destination = (
            f"datapool/static/"
            f"{sample_id}/"
            f"{sample_variant}/"
            f"{sha256}/"
        )

        command = (
            f'mc rm --recursive --force --quiet "{destination}"'
        )

        self.remnux_vm.run_bash(command)