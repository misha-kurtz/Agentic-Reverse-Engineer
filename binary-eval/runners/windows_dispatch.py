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

        '''
        Download the original sample from MinIO and verify its integrity.

        1. Creates the destination directory on the Windows VM.
        2. Downloads sample.bin using the presigned GET URL.
        3. Checks whether the HTTP download succeeded.
        4. Calculates the downloaded file's SHA-256.
        5. Compares the calculated hash against the expected SHA-256.
        6. Raises an error if the download or integrity verification fails.
        '''
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


    def verify_and_upload(
        self,
        presigned_url: str,
        expected_sha256: str,
        guest_recovered_path: PureWindowsPath,
    ) -> None:
        '''
        Verify the recovered payload SHA-256 and upload it to MinIO
        using a presigned PUT URL.

        The upload is performed from the Windows analysis VM.

        PowerShell failures are propagated through explicit exit codes.
        '''

        recovered_path = str(guest_recovered_path)
        expected_sha256 = expected_sha256.lower()

        script = f'''
$ErrorActionPreference = "Stop"

try {{
    $recoveredPath = "{recovered_path}"
    $expectedSha256 = "{expected_sha256}"
    $presignedUrl = "{presigned_url}"

    if (-not (Test-Path -LiteralPath $recoveredPath -PathType Leaf)) {{
        throw "Recovered payload does not exist: $recoveredPath"
    }}

    $actualSha256 = (Get-FileHash -LiteralPath $recoveredPath -Algorithm SHA256).Hash.ToLowerInvariant()

    if ($actualSha256 -ne $expectedSha256) {{
        throw "Recovered payload SHA-256 mismatch. Expected: $expectedSha256 Actual: $actualSha256"
    }}

    curl.exe --fail-with-body --show-error --request PUT --upload-file "$recoveredPath" "$presignedUrl"

    if ($LASTEXITCODE -ne 0) {{
        throw "Recovered payload upload failed. curl.exe exit code: $LASTEXITCODE"
    }}

    exit 0
}}
catch {{
    Write-Error $_
    exit 1
}}
'''

        self.windows_vm.run_powershell(script)


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

        self.windows_vm.run_powershell(
            f'if (Test-Path -LiteralPath "{guest_sample_dir}") {{ '
            f'Remove-Item -LiteralPath "{guest_sample_dir}" '
            f'-Recurse -Force '
            f'}}'
        )