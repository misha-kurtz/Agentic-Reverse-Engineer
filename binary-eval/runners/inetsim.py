# binary-eval/runners/inetsim.py

from pathlib import PurePosixPath

from runners.vmware import VMwareRunner


class INetSimRunner:
    def __init__(
        self,
        ubuntu_vm: VMwareRunner,
    ):
        self.ubuntu_vm = ubuntu_vm

    def start(
        self,
        dynamic_dir: PurePosixPath,
    ) -> None:

        inetsim_output_dir = dynamic_dir / "inetsim"

        self.ubuntu_vm.run_bash(
            f'mkdir -p "{inetsim_output_dir}"'
        )

        self.ubuntu_vm.run_bash(
            "sudo systemctl start inetsim"
        )

    def is_running(self) -> bool:

        try:
            self.ubuntu_vm.run_bash(
                "systemctl is-active --quiet inetsim"
            )
            return True

        except RuntimeError:
            return False

    def stop(self) -> None:

        self.ubuntu_vm.run_bash(
            "sudo systemctl stop inetsim"
        )