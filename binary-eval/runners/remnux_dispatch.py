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