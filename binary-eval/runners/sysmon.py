# binary-eval/runners/sysmon.py

from pathlib import PureWindowsPath

from runners.vmware import VMwareRunner


class SysmonRunner:
    def __init__(self, windows_vm: VMwareRunner):
        self.windows_vm = windows_vm

    def prepare_output_dir(
        self,
        sample_id: str,
        sample_variant: str,
        sha256: str,
    ) -> PureWindowsPath:
        output_dir = PureWindowsPath(
            rf"C:\binary-eval\work\{sample_id}\{sample_variant}\{sha256}\dynamic\sysmon"
        )

        self.windows_vm.run_powershell(
            f'New-Item -ItemType Directory -Force -Path "{output_dir}" | Out-Null'
        )

        return output_dir

    def is_installed(self) -> bool:
        command = (
            '$service = Get-Service | '
            'Where-Object { $_.Name -like "Sysmon*" } | '
            'Select-Object -First 1; '
            'if ($null -eq $service) { exit 1 }'
        )

        try:
            self.windows_vm.run_powershell(command)
            return True
        except RuntimeError:
            return False

    def clear_log(self) -> None:
        self.windows_vm.run_powershell(
            'wevtutil cl "Microsoft-Windows-Sysmon/Operational"'
        )

    def export_log(self, output_dir: PureWindowsPath) -> PureWindowsPath:
        output_path = output_dir / "sysmon.evtx"

        self.windows_vm.run_powershell(
            f'wevtutil epl "Microsoft-Windows-Sysmon/Operational" '
            f'"{output_path}" /ow:true'
        )

        return output_path