from pathlib import Path

from runners.vmware import VMwareRunner


class MinioDispatchRunner:
    def __init__(self, datapool_vm: VMwareRunner):
        self.datapool_vm = datapool_vm

    def generate_presigned_url(
        self,
        sample_id: str,
        sha256: str,
        host_temp_path: Path,
    ) -> str:

        object_path = (
            f"datapool-dispatch/"
            f"samples-staging/"
            f"{sample_id}/original/"
            f"{sha256}/sample.bin"
        )

        guest_url_file = "/tmp/presigned_url.txt"

        command = (
            f'mc share download --expire 5m "{object_path}" '
            "| grep -Eo \"https?://[^[:space:]]+\" "
            f"> {guest_url_file}"
        )

        self.datapool_vm.run_bash(command)

        self.datapool_vm.copy_from_guest(
            guest_url_file,
            str(host_temp_path),
        )

        presigned_url = host_temp_path.read_text().strip()

        if not presigned_url.startswith(("http://", "https://")):
            raise RuntimeError(
                f"Failed to generate presigned URL: {presigned_url!r}"
            )

        return presigned_url