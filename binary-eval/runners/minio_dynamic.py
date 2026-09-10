# binary-eval/runners/minio_dynamic.py

from pathlib import PurePosixPath, PureWindowsPath

from runners.vmware import VMwareRunner


class MinioDynamicRunner:
    def __init__(
        self,
        vm: VMwareRunner,
        alias: str,
        platform: str,
    ):
        self.vm = vm
        self.alias = alias
        self.platform = platform

        if self.platform not in {"linux", "windows"}:
            raise ValueError(
                "platform must be 'linux' or 'windows'"
            )

    def _run(self, command: str) -> None:

        if self.platform == "linux":
            self.vm.run_bash(command)

        elif self.platform == "windows":
            self.vm.run_powershell(command)

    def upload(
        self,
        guest_artifact_path: PurePosixPath | PureWindowsPath,
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

        command = (
            f'mc cp "{guest_artifact_path}" "{destination}"'
        )

        self._run(command)

    def upload_directory(
        self,
        guest_directory_path: PurePosixPath | PureWindowsPath,
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

        command = (
            f'mc cp --recursive '
            f'"{guest_directory_path}" '
            f'"{destination}"'
        )

        self._run(command)

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

        command = (
            f'mc rm --recursive --force --quiet "{destination}"'
        )

        self._run(command)

    def clean_dynamic_prefix(
        self,
        sample_id: str,
        sample_variant: str,
        sha256: str,
    ) -> None:

        destination = (
            f"{self.alias}/dynamic/"
            f"{sample_id}/"
            f"{sample_variant}/"
            f"{sha256}/"
        )

        command = (
            f'mc rm --recursive --force --quiet "{destination}"'
        )

        self._run(command)