from pathlib import PurePosixPath

from runners.vmware import VMwareRunner


class RemnuxDispatchRunner:
    def __init__(self, remnux_vm: VMwareRunner):
        self.remnux_vm = remnux_vm

    def download_and_verify(
        self,
        presigned_url: str,
        expected_sha256: str,
        guest_sample_path: PurePosixPath,
    ) -> None:

        guest_sample_path = str(guest_sample_path)
        guest_dir = str(PurePosixPath(guest_sample_path).parent)

        command = (
            f'mkdir -p "{guest_dir}" && '
            f'curl --fail --location "{presigned_url}" '
            f'-o "{guest_sample_path}" && '
            f'echo "{expected_sha256}  {guest_sample_path}" '
            '| sha256sum --check'
        )

        self.remnux_vm.run_bash(command)

    def clean_sample_workspace(
        self,
        sample_id: str,
        sample_variant: str,
        sha256: str,
    ) -> None:

        guest_sample_dir = PurePosixPath(
            f"/home/misha.kurtz/binary-eval/work/"
            f"{sample_id}/{sample_variant}/{sha256}"
        )

        command = (
            f'rm -rf "{guest_sample_dir}"'
        )

        self.remnux_vm.run_bash(command)