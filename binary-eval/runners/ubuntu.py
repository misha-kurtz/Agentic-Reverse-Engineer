# binary-eval/runners/ubuntu.py

from pathlib import PurePosixPath

from runners.vmware import VMwareRunner


class UbuntuRunner:
    def __init__(
        self,
        ubuntu_vm: VMwareRunner,
    ):
        self.ubuntu_vm = ubuntu_vm

    def clean_dynamic_workspace(
        self,
        sample_id,
        sample_variant,
        sha256,
    ):
        guest_sample_dir = PurePosixPath(
            f"/home/kurtz/binary-eval/work/"
            f"{sample_id}/{sample_variant}/{sha256}"
        )

        self.ubuntu_vm.run_bash(
            f"sudo -S -p '' "
            f'rm -rf "{guest_sample_dir}" '
            f"< /home/kurtz/.inetsim"
        )

    def prepare_dynamic_workspace(
        self,
        sample_id: str,
        sample_variant: str,
        sha256: str,
    ) -> PurePosixPath:

        guest_dynamic_dir = PurePosixPath(
            f"/home/kurtz/binary-eval/work/"
            f"{sample_id}/{sample_variant}/{sha256}/dynamic"
        )

        command = (
            f'mkdir -p '
            f'"{guest_dynamic_dir}/inetsim" '
            f'"{guest_dynamic_dir}/wireshark"'
        )

        self.ubuntu_vm.run_bash(command)

        return guest_dynamic_dir