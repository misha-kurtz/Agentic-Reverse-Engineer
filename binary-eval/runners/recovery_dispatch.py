# binary-eval/runners/recovery_dispatch.py

from pathlib import Path, PureWindowsPath
from zipfile import ZIP_DEFLATED, ZipFile

from runners.vmware import VMwareRunner

'''
Payload Recovery Dispatch Runner

Purpose:
    Provide the host-to-guest deployment and execution interface for
    deterministic payload recovery inside the Windows analysis VM.

Responsibilities:
    1. Package the required recovery modules from the host repository
       into a ZIP archive while preserving their directory structure.
    2. Transfer the archive to the Windows VM and extract its contents.
    3. Invoke the Windows recovery entry point using VMware guest operations.
    4. Retrieve the generated recovery metadata from the Windows VM.

This runner handles VMware operations without implementing the underlying
UPX unpacking or Hyperion runtime decryption algorithms.
'''

class RecoveryDispatchRunner:
    def __init__(
        self,
        windows_vm: VMwareRunner,
        python_path: PureWindowsPath,
    ):
        self.windows_vm = windows_vm
        self.python_path = python_path

    def package(
        self,
        repository_root: Path,
        archive_path: Path,
    ) -> Path:
        '''
        Package the deterministic payload recovery scripts into a ZIP archive.
        '''

        required_files = [
            "runners/debugger.py",
            "runners/cfg.py",
            "runners/iat.py",
            "runners/import_resolver.py",
            "runners/import_rebuilder.py",
            "runners/iat_patcher.py",
            "runners/memory_dump.py",
            "runners/reconstruction.py",
            "runners/post_oep_recovery.py",
            "workflows/payload_recovery/runtime_unpack.py",
            "workflows/payload_recovery/runtime_decrypt.py",
            "workflows/payload_recovery/recovery_entry.py",
        ]

        repository_root = Path(repository_root).resolve()
        archive_path = Path(archive_path).resolve()

        for relative_path in required_files:
            source_path = repository_root / relative_path

            if not source_path.is_file():
                raise FileNotFoundError(f"Required recovery module not found: {source_path}")

        archive_path.parent.mkdir(parents=True, exist_ok=True)

        with ZipFile(archive_path, "w", ZIP_DEFLATED) as archive:
            for relative_path in required_files:
                source_path = repository_root / relative_path
                archive.write(source_path, arcname=relative_path)

        return archive_path


    def deploy(
        self,
        host_archive_path: Path,
        guest_archive_path: PureWindowsPath,
        guest_code_dir: PureWindowsPath,
    ) -> None:
        '''
        Transfer and extract the payload recovery code inside the Windows VM.

        recovery.zip
        ├── runners/
        │   ├── debugger.py
        │   ├── cfg.py
        │   ├── iat.py
        │   ├── import_resolver.py
        │   ├── import_rebuilder.py
        │   ├── iat_patcher.py
        │   ├── memory_dump.py
        │   ├── reconstruction.py
        │   └── post_oep_recovery.py
        └── workflows/
            └── payload_recovery/
                ├── runtime_unpack.py
                ├── runtime_decrypt.py
                └── recovery_entry.py
        '''

        if not host_archive_path.is_file():
            raise FileNotFoundError(f"Recovery archive not found: {host_archive_path}")

        self.windows_vm.run_powershell(
            f'New-Item -ItemType Directory -Force -Path "{guest_archive_path.parent}" | Out-Null'
        )

        self.windows_vm.copy_to_guest(str(host_archive_path), str(guest_archive_path))

        self.windows_vm.run_powershell(
            f'$ErrorActionPreference = "Stop"; '
            f'Expand-Archive -LiteralPath "{guest_archive_path}" -DestinationPath "{guest_code_dir}" -Force'
        )

        entry_path = guest_code_dir / "workflows" / "payload_recovery" / "recovery_entry.py"

        self.windows_vm.run_powershell(
            f'if (-not (Test-Path -LiteralPath "{entry_path}")) {{ throw "Recovery entry point not found" }}'
        )

    def execute(
        self,
        recovery_method: str,
        guest_sample_path: PureWindowsPath,
        guest_output_dir: PureWindowsPath,
        guest_code_dir: PureWindowsPath,
        cdb_path: PureWindowsPath,
    ) -> None:
        '''
        Execute the requested recovery entry point inside Windows.
        '''

        entry_module = "workflows.payload_recovery.recovery_entry"

        command = (
            f'$ErrorActionPreference = "Stop"; '
            f'Set-Location -LiteralPath "{guest_code_dir}"; '
            f'& "{self.python_path}" -m {entry_module} '
            f'--method "{recovery_method}" '
            f'--input "{guest_sample_path}" '
            f'--output "{guest_output_dir}" '
            f'--cdb-path "{cdb_path}"; '
            f'if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}'
        )

        self.windows_vm.run_powershell(command)

    def retrieve_result(
        self,
        guest_result_path: PureWindowsPath,
        host_result_path: Path,
    ) -> None:
        '''
        Retrieve payload recovery metadata from the Windows VM.
        '''

        host_result_path.parent.mkdir(parents=True, exist_ok=True)

        self.windows_vm.copy_from_guest(str(guest_result_path), str(host_result_path))

        if not host_result_path.is_file():
            raise FileNotFoundError(f"Recovery result was not retrieved: {host_result_path}")

