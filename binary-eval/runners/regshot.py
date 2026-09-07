# binary-eval/runners/regshot.py

import base64
import time
import textwrap

from pathlib import PureWindowsPath

from runners.vmware import VMwareRunner


class RegshotRunner:
    def __init__(
        self,
        windows_vm: VMwareRunner,
        python_path: PureWindowsPath,
        regshot_path: PureWindowsPath,
    ):
        self.windows_vm = windows_vm
        self.python_path = python_path
        self.regshot_path = regshot_path

    def prepare_output_dir(
        self,
        sample_id: str,
        sample_variant: str,
        sha256: str,
    ) -> PureWindowsPath:

        output_dir = PureWindowsPath(
            rf"C:\binary-eval\work\{sample_id}\{sample_variant}\{sha256}\dynamic\regshot"
        )

        self.windows_vm.run_powershell(
            f'New-Item -ItemType Directory -Force -Path "{output_dir}" | Out-Null'
        )

        return output_dir

    def start(self, output_dir: PureWindowsPath) -> None:
        command = (
            f'$action = New-ScheduledTaskAction '
            f'-Execute "{self.regshot_path}" '
            f'-WorkingDirectory "{self.regshot_path.parent}"; '
            f'$principal = New-ScheduledTaskPrincipal '
            f'-UserId "misha.kurtz" '
            f'-LogonType Interactive '
            f'-RunLevel Highest; '
            f'$task = New-ScheduledTask -Action $action -Principal $principal; '
            f'Register-ScheduledTask '
            f'-TaskName "BinaryEval-Regshot-App" '
            f'-InputObject $task '
            f'-Force | Out-Null; '
            f'Start-ScheduledTask -TaskName "BinaryEval-Regshot-App"'
        )

        self.windows_vm.run_powershell(command)

        deadline = time.time() + 15

        while time.time() < deadline:
            if self.is_running():
                break
            time.sleep(1)
        else:
            raise RuntimeError("Regshot failed to start")

        self._write_pid_file()

        code = f'''
from pywinauto import Application

with open(r"C:\\binary-eval\\regshot.pid", "r") as f:
    pid = int(f.read().strip())

with open(r"C:\\binary-eval\\regshot-start-status.txt", "w") as f:
    f.write("PID loaded")

app = Application(backend="win32").connect(process=pid)

with open(r"C:\\binary-eval\\regshot-start-status.txt", "w") as f:
    f.write("Connected")

window = app.top_window()

with open(r"C:\\binary-eval\\regshot-start-status.txt", "w") as f:
    f.write("Window found")

window.restore()

with open(r"C:\\binary-eval\\regshot-start-status.txt", "w") as f:
    f.write("Window restored")

output = window.child_window(best_match="Output path:Edit")
output.set_edit_text(r"{output_dir}")

with open(r"C:\\binary-eval\\regshot-start-status.txt", "w") as f:
    f.write("Output path set")

txt = window.child_window(title="Plain &TXT", class_name="Button")
txt.check()

with open(r"C:\\binary-eval\\regshot-start-status.txt", "w") as f:
    f.write("Start configuration complete")
'''

        self._run_python(code)

    def is_running(self) -> bool:
        command = (
            '$process = Get-Process | '
            'Where-Object { $_.ProcessName -like "Regshot*" }; '
            'if ($null -eq $process) { exit 1 }'
        )

        try:
            self.windows_vm.run_powershell(command)
            return True
        except RuntimeError:
            return False

    def _write_pid_file(self) -> None:
        command = (
            '$process = Get-Process | '
            'Where-Object { $_.ProcessName -like "Regshot*" } | '
            'Select-Object -First 1; '
            'if ($null -eq $process) { exit 1 }; '
            '$process.Id | Set-Content "C:\\binary-eval\\regshot.pid"'
        )

        self.windows_vm.run_powershell(command)

    def take_first_snapshot(self) -> None:
        self._take_snapshot("&1st shot", "&2nd shot")

    def take_second_snapshot(self) -> None:
        self._take_snapshot("&2nd shot", "C&ompare")

    def _take_snapshot(self, button_name: str, completion_button_name: str) -> None:
        code = f'''
from pywinauto import Application, Desktop
import time

with open(r"C:\\binary-eval\\regshot.pid", "r") as f:
    pid = int(f.read().strip())

app = Application(backend="win32").connect(process=pid)
window = app.top_window()

window.restore()
window.set_focus()

button = window.child_window(
    title="{button_name}",
    class_name="Button"
)

button.wait("enabled", timeout=10)
button.click_input()

time.sleep(0.5)

popup = Desktop(backend="win32").window(class_name="#32768")
popup.wait("visible", timeout=10)

menu = popup.menu()
shot = menu.get_menu_path("Shot")[0]
shot.click_input()

app.wait_cpu_usage_lower(
    threshold=5,
    timeout=180
)

deadline = time.time() + 30

while time.time() < deadline:
    completion_button = window.child_window(
        title="{completion_button_name}",
        class_name="Button"
    )

    if completion_button.exists() and completion_button.is_enabled():
        break

    time.sleep(1)
else:
    raise RuntimeError(
        "Regshot snapshot scan ended, but "
        "{completion_button_name} never became enabled"
    )
'''
        self._run_python(code)

    def compare(self, output_dir: PureWindowsPath) -> PureWindowsPath:
        code = '''
from pywinauto import Application
import time

with open(r"C:\\binary-eval\\regshot.pid", "r") as f:
    pid = int(f.read().strip())

app = Application(backend="win32").connect(process=pid)
window = app.top_window()
window.restore()

button = window.child_window(title="C&ompare", class_name="Button")
button.wait("enabled", timeout=30)
button.click_input()

time.sleep(2)
'''
        self._run_python(code)

        return output_dir

    def clear(self) -> None:
        code = '''
from pywinauto import Application

with open(r"C:\\binary-eval\\regshot.pid", "r") as f:
    pid = int(f.read().strip())

app = Application(backend="win32").connect(process=pid)
window = app.top_window()

window.restore()
window.set_focus()

button = window.child_window(title="&Clear", class_name="Button")
button.wait("enabled", timeout=10)
button.click_input()
'''
        self._run_python(code)

    def stop(self) -> None:
        self.windows_vm.run_powershell(
            'Get-Process | Where-Object { $_.ProcessName -like "Regshot*" } '
            '| Stop-Process -Force -ErrorAction SilentlyContinue; '
            'Unregister-ScheduledTask -TaskName "BinaryEval-Regshot-App" '
            '-Confirm:$false -ErrorAction SilentlyContinue; '
            'Remove-Item "C:\\binary-eval\\regshot.pid" '
            '-Force -ErrorAction SilentlyContinue'
        )

    def _run_python(self, code: str) -> None:
        helper_path = r"C:\binary-eval\regshot-helper.py"
        done_path = r"C:\binary-eval\regshot-helper.done"
        log_path = r"C:\binary-eval\regshot-pywinauto.log"

        wrapped_code = (
            "import traceback\n\n"
            "try:\n"
            f"{textwrap.indent(code.strip(), '    ')}\n"
            "except Exception:\n"
            f'    with open(r"{log_path}", "w", encoding="utf-8") as f:\n'
            "        traceback.print_exc(file=f)\n"
            "    raise\n"
            "finally:\n"
            f'    with open(r"{done_path}", "w", encoding="utf-8") as f:\n'
            '        f.write("done")\n'
        )

        encoded = base64.b64encode(wrapped_code.encode("utf-8")).decode("ascii")

        command = (
            f'$bytes = [Convert]::FromBase64String("{encoded}"); '
            f'[System.IO.File]::WriteAllBytes("{helper_path}", $bytes); '
            f'Remove-Item "{done_path}" -Force -ErrorAction SilentlyContinue; '
            f'Remove-Item "{log_path}" -Force -ErrorAction SilentlyContinue; '
            f'$action = New-ScheduledTaskAction -Execute "{self.python_path}" -Argument \'"{helper_path}"\'; '
            f'$principal = New-ScheduledTaskPrincipal -UserId "misha.kurtz" -LogonType Interactive -RunLevel Highest; '
            f'$task = New-ScheduledTask -Action $action -Principal $principal; '
            f'Register-ScheduledTask -TaskName "BinaryEval-Regshot" -InputObject $task -Force | Out-Null; '
            f'Start-ScheduledTask -TaskName "BinaryEval-Regshot"'
        )

        self.windows_vm.run_powershell(command)

        deadline = time.time() + 180

        while time.time() < deadline:
            try:
                self.windows_vm.run_powershell(
                    f'if (-not (Test-Path "{done_path}")) {{ exit 1 }}'
                )
                break
            except RuntimeError:
                time.sleep(1)
        else:
            raise RuntimeError("Regshot GUI helper did not complete within 180 seconds")

        try:
            self.windows_vm.run_powershell(
                f'if (Test-Path "{log_path}") {{ exit 1 }}'
            )
        except RuntimeError:
            raise RuntimeError(
                rf"Regshot GUI helper failed. Check {log_path}"
            )

        self.windows_vm.run_powershell(
            'Unregister-ScheduledTask -TaskName "BinaryEval-Regshot" '
            '-Confirm:$false -ErrorAction SilentlyContinue'
        )

