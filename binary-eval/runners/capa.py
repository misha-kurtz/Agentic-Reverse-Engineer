from pathlib import PurePosixPath

from runners.vmware import VMwareRunner


class CAPARunner:
    def __init__(self, remnux_vm: VMwareRunner):
        self.remnux_vm = remnux_vm

    def analyze(
        self,
        guest_sample_path: PurePosixPath,
        guest_output_path: PurePosixPath,
    ) -> None:

        sample_path = str(guest_sample_path)
        output_path = str(guest_output_path)
        output_dir = str(guest_output_path.parent)

        command = (
            f'mkdir -p "{output_dir}" && '
            f'capa -j "{sample_path}" > "{output_path}"'
        )

        self.remnux_vm.run_bash(command)