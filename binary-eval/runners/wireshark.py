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

        try:
            self.ubuntu_vm.run_bash(
                "pgrep -x tshark > /dev/null"
            )
            return True

        except RuntimeError:
            return False

    def stop(
        self,
        dynamic_dir: PurePosixPath,
    ) -> None:

        pid_file = dynamic_dir / "tshark.pid"

        command = (
            'pkill -TERM -x tshark 2>/dev/null || true; '
            'pkill -TERM -x dumpcap 2>/dev/null || true; '
            'sleep 1; '
            f'rm -f "{pid_file}"; '
            'sync'
        )

        self.ubuntu_vm.run_bash(command)