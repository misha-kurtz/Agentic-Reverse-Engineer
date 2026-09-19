# binary-eval/runners/noriben.py

import time
from pathlib import PureWindowsPath

from runners.vmware import VMwareRunner


class NoribenRunner:
    def __init__(
        self,
        windows_vm: VMwareRunner,
        python_path: PureWindowsPath,
        noriben_path: PureWindowsPath,
        procmon_config_path: PureWindowsPath,
    ):
        self.windows_vm = windows_vm
        self.python_path = python_path
        self.noriben_path = noriben_path
        self.procmon_config_path = procmon_config_path

    def prepare_output_dir(
        self,
        sample_id: str,
        sample_variant: str,
        sha256: str,
    ) -> PureWindowsPath:

        output_dir = PureWindowsPath(
            rf"C:\binary-eval\work\{sample_id}"
            rf"\{sample_variant}\{sha256}"
            rf"\dynamic\noriben"
        )

        self.windows_vm.run_powershell(
            f'New-Item -ItemType Directory -Force '
            f'-Path "{output_dir}" | Out-Null'
        )

        return output_dir

    def verify_config(self) -> None:
        command = (
            f'if (-not (Test-Path "{self.procmon_config_path}")) {{ '
            f'throw "Procmon configuration file not found: '
            f'{self.procmon_config_path}" '
            f'}}'
        )

        self.windows_vm.run_powershell(command)

    def start(
        self,
        output_dir: PureWindowsPath,
        capture_seconds: int,
    ) -> None:

        self.verify_config()

        arguments = (
            f'"{self.noriben_path}" '
            f'--headless '
            f'--debug '
            f'-t {capture_seconds} '
            f'-f "{self.procmon_config_path}" '
            f'--output "{output_dir}"'
        )

        command = (
            f'Start-Process '
            f'-FilePath "{self.python_path}" '
            f'-ArgumentList \'{arguments}\' '
            f'-WindowStyle Hidden'
        )

        self.windows_vm.run_powershell(command)

    def is_running(self) -> bool:
        command = (
            '$process = Get-CimInstance Win32_Process '
            '| Where-Object { '
            '$_.Name -like "python*.exe" -and '
            '$_.CommandLine -like "*Noriben.py*" '
            '}; '
            'if ($null -eq $process) { exit 1 }'
        )

        try:
            self.windows_vm.run_powershell(command)
            return True
        except RuntimeError:
            return False

    def wait_for_completion(
        self,
        timeout: int = 300,
        interval: int = 2,
    ) -> None:

        deadline = time.time() + timeout

        while time.time() < deadline:
            if not self.is_running():
                return

            time.sleep(interval)

        raise RuntimeError(
            "Noriben did not complete within expected time"
        )

    def stop(self) -> None:
        command = (
            '$noriben = Get-CimInstance Win32_Process '
            '| Where-Object { '
            '$_.CommandLine -like "*Noriben.py*" '
            '}; '
            'foreach ($process in $noriben) { '
            'Stop-Process -Id $process.ProcessId -Force '
            '}; '
            '$procmon = Get-Process '
            '-Name Procmon,Procmon64 '
            '-ErrorAction SilentlyContinue; '
            'if ($procmon) { '
            '& "$($procmon[0].Path)" /Terminate '
            '}'
        )

        self.windows_vm.run_powershell(command)