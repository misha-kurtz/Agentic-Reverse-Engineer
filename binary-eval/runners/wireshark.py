# binary-eval/runners/wireshark.py

from pathlib import PurePosixPath

from runners.vmware import VMwareRunner


class WiresharkRunner:
    def __init__(
        self,
        ubuntu_vm: VMwareRunner,
        interface: str,
    ):
        self.ubuntu_vm = ubuntu_vm
        self.interface = interface

    def start(
        self,
        dynamic_dir: PurePosixPath,
    ) -> PurePosixPath:

        pcap_dir = dynamic_dir / "wireshark"
        pcap_path = pcap_dir / "traffic.pcapng"
        pid_file = dynamic_dir / "tshark.pid"
        log_file = dynamic_dir / "tshark.log"

        command = (
            f'mkdir -p "{pcap_dir}" && '
            f'nohup tshark '
            f'-i "{self.interface}" '
            f'-w "{pcap_path}" '
            f'> "{log_file}" 2>&1 & '
            f'echo $! > "{pid_file}"'
        )

        self.ubuntu_vm.run_bash(command)

        return pcap_path

    def is_running(
        self,
        dynamic_dir: PurePosixPath,
    ) -> bool:

        pid_file = dynamic_dir / "tshark.pid"

        command = (
            f'test -f "{pid_file}" && '
            f'kill -0 "$(cat "{pid_file}")"'
        )

        try:
            self.ubuntu_vm.run_bash(command)
            return True

        except RuntimeError:
            return False

    def stop(
        self,
        dynamic_dir: PurePosixPath,
    ) -> None:

        pid_file = dynamic_dir / "tshark.pid"

        command = (
            f'if [ -f "{pid_file}" ]; then '
            f'pid="$(cat "{pid_file}")"; '
            f'kill "$pid" 2>/dev/null || true; '
            f'while kill -0 "$pid" 2>/dev/null; do '
            f'sleep 0.2; '
            f'done; '
            f'rm -f "{pid_file}"; '
            f'fi; '
            f'sync'
        )

        self.ubuntu_vm.run_bash(command)