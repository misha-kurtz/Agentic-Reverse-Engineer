# binary-eval/runners/vmware.py

import os
import subprocess
import time
import base64
from pathlib import Path


class VMwareRunner:
    def __init__(
        self,
        vmx_path: str,
        guest_username: str,
        password_env_var: str,
        vmrun_path: str = "vmrun",
    ):
        self.vmx_path = str(Path(vmx_path))
        self.guest_username = guest_username
        self.guest_password = os.getenv(password_env_var)
        self.vmrun_path = vmrun_path

        if not self.guest_password:
            raise RuntimeError(
                f"{password_env_var} environment variable is not set"
            )

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        command = [
            self.vmrun_path,
            "-T", "ws",
            *args,
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"vmrun failed with exit code {result.returncode}\n"
                f"stdout: {result.stdout.strip()}\n"
                f"stderr: {result.stderr.strip()}"
            )

        return result

    def start(self, nogui: bool = True) -> None:
        """
        Start the VM if it is not already running.
        """
        if self.is_running():
            return

        args = ["start", self.vmx_path]

        if nogui:
            args.append("nogui")

        self._run(args)

    def check_tools(self) -> bool:
        """
        Check whether VMware Tools is running in the guest.
        """
        result = self._run([
            "checkToolsState",
            self.vmx_path,
        ])

        return "running" in result.stdout.lower()

    def wait_for_guest(
        self,
        timeout=60,
        interval=2,
        shell: str = "bash",
    ):
        deadline = time.time() + timeout
        last_error = None

        while time.time() < deadline:
            try:
                if shell == "windows":
                    self.run_program(
                        r"C:\Windows\System32\whoami.exe"
                    )
                else:
                    self.run_bash("true")

                return

            except RuntimeError as exc:
                last_error = exc
                time.sleep(interval)

        raise RuntimeError(
            f"Guest VM did not become ready within {timeout} seconds\n"
            f"Last error:\n{last_error}"
        )

    def run_bash(self, command: str) -> str:
        """
        Execute a Bash command inside the guest.

        Requires VMware Tools / open-vm-tools to be running.
        """
        result = self._run([
            "-gu", self.guest_username,
            "-gp", self.guest_password,
            "runScriptInGuest",
            self.vmx_path,
            "/bin/bash",
            command,
        ])

        return result.stdout

    def run_program(
        self,
        program_path: str,
        arguments: list[str] | None = None,
    ) -> str:

        args = [
            "-gu", self.guest_username,
            "-gp", self.guest_password,
            "runProgramInGuest",
            self.vmx_path,
            program_path,
        ]

        if arguments:
            args.extend(arguments)

        result = self._run(args)

        return result.stdout

    def run_powershell(self, command: str) -> str:
        encoded_command = base64.b64encode(
            command.encode("utf-16le")
        ).decode("ascii")

        return self.run_program(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            [
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded_command,
            ],
        )

    def copy_from_guest(self, guest_path: str, host_path: str) -> None:
        """
        Copy a file from the guest VM to the physical host.
        """
        self._run([
            "-gu", self.guest_username,
            "-gp", self.guest_password,
            "copyFileFromGuestToHost",
            self.vmx_path,
            guest_path,
            host_path,
        ])

    def is_running(self) -> bool:
        """
        Check if the VM is currently running.
        """
        result = subprocess.run(
            [
                self.vmrun_path,
                "-T", "ws",
                "list",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"vmrun list failed with exit code {result.returncode}\n"
                f"stdout: {result.stdout.strip()}\n"
                f"stderr: {result.stderr.strip()}"
            )

        return self.vmx_path in result.stdout

    def stop(self, soft: bool = True) -> None:
        """
        Stop the VM if it is currently running.
        """
        if not self.is_running():
            return

        mode = "soft" if soft else "hard"

        self._run([
            "stop",
            self.vmx_path,
            mode,
        ])


