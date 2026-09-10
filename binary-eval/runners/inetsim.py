from pathlib import PurePosixPath

from runners.vmware import VMwareRunner


class INetSimRunner:
    def __init__(self, ubuntu_vm):
        self.ubuntu_vm = ubuntu_vm
        self.file = "/home/kurtz/.inetsim"

    def _run_sudo(self, command: str) -> None:
        self.ubuntu_vm.run_bash(f"sudo -S -p '' {command} < {self.file}")

    def start(self, dynamic_dir):
        inetsim_output_dir = dynamic_dir / "inetsim"

        self.ubuntu_vm.run_bash(f'mkdir -p "{inetsim_output_dir}"')

        self._run_sudo("systemctl start inetsim")

    def is_running(self):
        try:
            self.ubuntu_vm.run_bash("systemctl is-active --quiet inetsim")
            return True
        except RuntimeError:
            return False

    def stop(self):
        self._run_sudo("systemctl stop inetsim")

    def clean_runtime_artifacts(self) -> None:

        if self.is_running():
            self.stop()

        self._run_sudo("truncate -s 0 /var/log/inetsim/debug.log")

        self._run_sudo("truncate -s 0 /var/log/inetsim/main.log")

        self._run_sudo("truncate -s 0 /var/log/inetsim/service.log")

        self._run_sudo("""bash -c 'rm -f /var/log/inetsim/report/*.txt'""")

        self._run_sudo("""bash -c 'rm -rf /var/lib/inetsim/http/postdata/*'""")

        self._run_sudo("""bash -c 'rm -rf /var/lib/inetsim/ftp/uploads/*'""")

    def collect_artifacts(
        self,
        dynamic_dir: PurePosixPath,
    ) -> PurePosixPath:

        inetsim_output_dir = dynamic_dir / "inetsim"

        logs_dir = inetsim_output_dir / "logs"
        reports_dir = inetsim_output_dir / "reports"
        postdata_dir = inetsim_output_dir / "postdata"
        ftp_uploads_dir = inetsim_output_dir / "ftp_uploads"

        self.ubuntu_vm.run_bash(f'mkdir -p "{logs_dir}" "{reports_dir}" "{postdata_dir}" "{ftp_uploads_dir}"')

        self._run_sudo(f'cp /var/log/inetsim/debug.log "{logs_dir}/debug.log"')

        self._run_sudo(f'cp /var/log/inetsim/main.log "{logs_dir}/main.log"')

        self._run_sudo(f'cp /var/log/inetsim/service.log "{logs_dir}/service.log"')

        self._run_sudo(f"""bash -c 'if compgen -G "/var/log/inetsim/report/*.txt" > /dev/null; then cp /var/log/inetsim/report/*.txt "{reports_dir}/"; fi'""")

        self._run_sudo(f"""bash -c 'if [ -d /var/lib/inetsim/http/postdata ] && [ "$(ls -A /var/lib/inetsim/http/postdata 2>/dev/null)" ]; then cp -a /var/lib/inetsim/http/postdata/. "{postdata_dir}/"; fi'""")

        self._run_sudo( f"""bash -c 'if [ -d /var/lib/inetsim/ftp/uploads ] && [ "$(ls -A /var/lib/inetsim/ftp/uploads 2>/dev/null)" ]; then cp -a /var/lib/inetsim/ftp/uploads/. "{ftp_uploads_dir}/"; fi'""")

        self._run_sudo(f'chown -R kurtz:kurtz "{inetsim_output_dir}"')

        return inetsim_output_dir

