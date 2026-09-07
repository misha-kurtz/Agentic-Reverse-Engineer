# binary-eval/runners/windows_dispatch.py

from pathlib import PureWindowsPath

from runners.vmware import VMwareRunner


class WindowsDispatchRunner:
    def __init__(self, windows_vm: VMwareRunner):
        self.windows_vm = windows_vm

    def download_and_verify(
        self,
        presigned_url: str,
        expected_sha256: str,
        guest_sample_path: PureWindowsPath,
    ) -> None:

        guest_sample_path = str(guest_sample_path)
        guest_dir = str(
            PureWindowsPath(guest_sample_path).parent
        )

        command = (
            f'New-Item -ItemType Directory -Force '
            f'-Path "{guest_dir}" | Out-Null; '
            f'curl.exe --fail --location '
            f'"{presigned_url}" '
            f'-o "{guest_sample_path}"; '
            f'if ($LASTEXITCODE -ne 0) {{ '
            f'exit $LASTEXITCODE '
            f'}}; '
            f'$hash = '
            f'(Get-FileHash '
            f'-Algorithm SHA256 '
            f'-Path "{guest_sample_path}").Hash.ToLower(); '
            f'if ($hash -ne "{expected_sha256.lower()}") {{ '
            f'Write-Error "SHA256 verification failed"; '
            f'exit 1 '
            f'}}'
        )

        self.windows_vm.run_powershell(command)

    def clean_sample_workspace(
        self,
        sample_id: str,
        sample_variant: str,
        sha256: str,
    ) -> None:

        guest_sample_dir = PureWindowsPath(
            rf"C:\binary-eval\work\{sample_id}"
            rf"\{sample_variant}\{sha256}"
        )

        command = (
            f'if (Test-Path "{guest_sample_dir}") {{ '
            f'Remove-Item '
            f'-Recurse '
            f'-Force '
            f'"{guest_sample_dir}" '
            f'}}'
        )

        self.windows_vm.run_powershell(command)

    def execute_sample(
        self,
        guest_sample_path: PureWindowsPath,
    ) -> None:

        self.windows_vm.run_program(
            str(guest_sample_path)
        )