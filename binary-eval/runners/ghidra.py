from pathlib import PurePosixPath

from runners.vmware import VMwareRunner


class GhidraRunner:
    def __init__(
        self,
        remnux_vm: VMwareRunner,
        analyze_headless_path: PurePosixPath,
        script_path: PurePosixPath,
    ):
        self.remnux_vm = remnux_vm
        self.analyze_headless_path = analyze_headless_path
        self.script_path = script_path

    def analyze(
        self,
        guest_sample_path: PurePosixPath,
        guest_output_dir: PurePosixPath,
    ) -> None:

        sample_path = str(guest_sample_path)
        output_dir = str(guest_output_dir)
        project_dir = f"{output_dir}/project"

        command = (
            f'rm -rf "{output_dir}" && '
            f'mkdir -p "{output_dir}" "{project_dir}" && '
            f'"{self.analyze_headless_path}" '
            f'"{project_dir}" analysis_project '
            f'-import "{sample_path}" '
            f'-scriptPath "{self.script_path}" '
            f'-postScript ExportStaticArtifacts.java "{output_dir}" '
            f'-deleteProject'
        )

        self.remnux_vm.run_bash(command)