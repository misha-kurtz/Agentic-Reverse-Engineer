import time
import shlex
from pathlib import Path
from urllib.parse import urlsplit

from runners.vmware import VMwareRunner


class MinioDispatchRunner:
    def __init__(self, datapool_vm: VMwareRunner):
        self.datapool_vm = datapool_vm

    def wait_for_minio(self, timeout=60, interval=2):
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                self.datapool_vm.run_bash(
                    "wget -q --spider "
                    "http://127.0.0.1:9000/minio/health/live"
                )
                return
            except RuntimeError:
                time.sleep(interval)

        raise RuntimeError(
            f"MinIO did not become ready within {timeout} seconds"
        )

    # Generate a presigned GET URL for downloading a sample from MinIO
    def generate_presigned_url_get(
        self,
        sample_id: str,
        sha256: str,
        sample_variant: str,
        host_temp_path: Path,
    ) -> str:

        object_path = (
            f"datapool-dispatch/"
            f"samples/"
            f"{sample_id}/{sample_variant}/"
            f"{sha256}/sample.bin"
        )

        guest_url_file = "/tmp/presigned_url.txt"

        command = (
            f'mc share download --expire 5m "{object_path}" '
            '| grep -Eo "https?://[^[:space:]]+X-Amz-[^[:space:]]+" '
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
                f"Failed to generate presigned GET URL: {presigned_url!r}"
            )

        return presigned_url

    # Generate a presigned PUT URL for uploading a recovered payload to MinIO
    def generate_presigned_url_put(
        self,
        sample_id: str,
        recovered_sha256: str,
        sample_variant: str,
        host_temp_path: Path,
    ) -> str:

        object_key = (
            f"{sample_id}/{sample_variant}/"
            f"recovered/{recovered_sha256}/recovered.bin"
        )

        guest_url_file = "/tmp/presigned_put_url.txt"

        script = (
            "import json\n"
            "from datetime import timedelta\n"
            "from pathlib import Path\n"
            "from urllib.parse import urlsplit\n"
            "from minio import Minio\n"
            "\n"
            "config_path = Path('/home/kurtz/.mc/config.json')\n"
            "\n"
            "with config_path.open('r', encoding='utf-8') as file:\n"
            "    config = json.load(file)\n"
            "\n"
            "alias = config['aliases']['recovered_payload_user']\n"
            "parsed_url = urlsplit(alias['url'])\n"
            "\n"
            "client = Minio(\n"
            "    endpoint=parsed_url.netloc,\n"
            "    access_key=alias['accessKey'],\n"
            "    secret_key=alias['secretKey'],\n"
            "    secure=parsed_url.scheme == 'https',\n"
            "    region='us-east-1',\n"
            ")\n"
            "\n"
            "url = client.presigned_put_object(\n"
            "    bucket_name='samples',\n"
            f"    object_name={object_key!r},\n"
            "    expires=timedelta(minutes=5),\n"
            ")\n"
            "\n"
            "print(url)\n"
        )

        command = (
            f"python3 -c {shlex.quote(script)} "
            f"> {shlex.quote(guest_url_file)}"
        )

        self.datapool_vm.run_bash(command)

        self.datapool_vm.copy_from_guest(
            guest_url_file,
            str(host_temp_path),
        )

        presigned_url = host_temp_path.read_text().strip()

        if not presigned_url.startswith(("http://", "https://")):
            raise RuntimeError(
                "Failed to generate presigned PUT URL"
            )

        return presigned_url