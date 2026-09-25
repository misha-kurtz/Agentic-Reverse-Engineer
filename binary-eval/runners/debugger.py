# binary-eval/runners/debugger.py

from __future__ import annotations

import queue
import re
import struct
import subprocess
import threading
import time

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


class DebuggerError(RuntimeError):
    pass


@dataclass(frozen=True)
class Instruction:
    address: int
    raw_bytes: bytes
    mnemonic: str
    operands: str
    text: str

    @property
    def size(self) -> int:
        return len(self.raw_bytes)


@dataclass(frozen=True)
class ModuleInfo:
    name: str
    base: int
    end: int


@dataclass(frozen=True)
class DirectJump:
    source: int
    target: int
    size: int


class CdbDebugger:
    """
    Thin synchronous wrapper around cdb.exe.

    This class intentionally contains no UPX-specific logic.
    """

    _PROMPT_RE = re.compile(
        r"(?:\d+:\d+(?::[a-z0-9]+)?|[a-z]+)>\s*$",
        re.IGNORECASE,
    )

    _REGISTER_RE = re.compile(
        r"\b([a-z0-9]+)=([0-9a-fA-F`]+)"
    )

    _MODULE_RE = re.compile(
        r"^\s*"
        r"([0-9a-fA-F`]+)\s+"
        r"([0-9a-fA-F`]+)\s+"
        r"(\S+)",
        re.MULTILINE,
    )

    # Typical CDB disassembly:
    #
    # 00007ff7`93d78e90 53              push    rbx
    #
    _DISASM_RE = re.compile(
        r"^\s*"
        r"([0-9a-fA-F`]+)\s+"
        r"([0-9a-fA-F]+)\s+"
        r"([a-zA-Z][a-zA-Z0-9.]*)"
        r"(?:\s+(.*?))?"
        r"\s*$"
    )

    def __init__(
        self,
        cdb_path: Path | str,
        command_timeout: float = 30.0,
    ):
        self.cdb_path = Path(cdb_path)
        self.command_timeout = command_timeout

        self._proc: subprocess.Popen | None = None
        self._output_queue: queue.Queue[str] = queue.Queue()
        self._reader_thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def launch(
        self,
        executable: Path | str,
        arguments: list[str] | None = None,
    ) -> None:

        executable = Path(executable)
        arguments = arguments or []

        if not self.cdb_path.exists():
            raise DebuggerError(
                f"CDB not found: {self.cdb_path}"
            )

        if not executable.exists():
            raise DebuggerError(
                f"Debug target not found: {executable}"
            )

        command = [
            str(self.cdb_path),

            # Debug child processes as well.
            "-o",

            # Target executable.
            str(executable),

            *arguments,
        ]

        self._proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=0,
        )

        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            daemon=True,
        )

        self._reader_thread.start()

        # CDB initially breaks in the loader/ntdll startup path.
        self._read_until_prompt(
            timeout=self.command_timeout,
        )

    def close(self) -> None:
        if self._proc is None:
            return

        try:
            if self._proc.poll() is None:
                self._send_raw("q\n")
                self._proc.wait(timeout=5)

        except Exception:
            self._proc.kill()

        self._proc = None

    def __enter__(self) -> "CdbDebugger":
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    # ------------------------------------------------------------------
    # Command transport
    # ------------------------------------------------------------------

    def _reader_loop(self) -> None:
        assert self._proc is not None
        assert self._proc.stdout is not None

        while True:
            char = self._proc.stdout.read(1)

            if char == "":
                break

            self._output_queue.put(char)

    def _send_raw(self, text: str) -> None:
        if self._proc is None:
            raise DebuggerError(
                "Debugger is not running"
            )

        if self._proc.poll() is not None:
            raise DebuggerError(
                f"CDB exited with code "
                f"{self._proc.returncode}"
            )

        assert self._proc.stdin is not None

        self._proc.stdin.write(text)
        self._proc.stdin.flush()

    def _read_until_prompt(
        self,
        timeout: float | None = None,
    ) -> str:

        timeout = timeout or self.command_timeout
        deadline = time.monotonic() + timeout

        output: list[str] = []

        while time.monotonic() < deadline:
            remaining = max(
                0.01,
                deadline - time.monotonic(),
            )

            try:
                char = self._output_queue.get(
                    timeout=min(
                        0.1,
                        remaining,
                    )
                )

            except queue.Empty:
                continue

            output.append(char)

            text = "".join(output)

            if self._PROMPT_RE.search(text):
                return text

        raise DebuggerError(
            "Timed out waiting for CDB prompt.\n"
            f"Partial output:\n{''.join(output)}"
        )

    def command(
        self,
        command: str,
        timeout: float | None = None,
    ) -> str:

        self._send_raw(
            command.rstrip() + "\n"
        )

        return self._read_until_prompt(
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def continue_execution(
        self,
        timeout: float = 120.0,
    ) -> str:

        return self.command(
            "g",
            timeout=timeout,
        )

    def step_into(self) -> str:
        return self.command("t")

    # ------------------------------------------------------------------
    # Registers
    # ------------------------------------------------------------------

    def get_register(
        self,
        name: str,
    ) -> int:

        output = self.command(
            f"r {name}"
        )

        wanted = name.lower()

        for register, value in self._REGISTER_RE.findall(
            output
        ):
            if register.lower() == wanted:
                return self._parse_address(
                    value
                )

        raise DebuggerError(
            f"Could not parse register "
            f"{name!r}:\n{output}"
        )

    def get_registers(
        self,
        *names: str,
    ) -> dict[str, int]:

        if not names:
            raise ValueError(
                "At least one register is required"
            )

        return {
            name.lower(): self.get_register(
                name
            )
            for name in names
        }

    # ------------------------------------------------------------------
    # Modules
    # ------------------------------------------------------------------

    def get_module(
        self,
        module_name: str,
    ) -> ModuleInfo:

        stem = Path(
            module_name
        ).stem

        output = self.command(
            f"lm m {stem}"
        )

        for match in self._MODULE_RE.finditer(
            output
        ):
            start, end, name = match.groups()

            if name.lower() == stem.lower():
                return ModuleInfo(
                    name=name,
                    base=self._parse_address(
                        start
                    ),
                    end=self._parse_address(
                        end
                    ),
                )

        raise DebuggerError(
            f"Could not locate module "
            f"{module_name!r}:\n"
            f"{output}"
        )

    # ------------------------------------------------------------------
    # Breakpoints
    # ------------------------------------------------------------------

    def set_breakpoint(
        self,
        address: int,
    ) -> None:

        self.command(
            f"bp 0x{address:x}"
        )

    def set_access_breakpoint(
        self,
        address: int,
        size: int = 8,
    ) -> None:

        if size not in (
            1,
            2,
            4,
            8,
        ):
            raise ValueError(
                "Hardware breakpoint size must be "
                "1, 2, 4, or 8"
            )

        if address % size != 0:
            raise ValueError(
                f"Address 0x{address:x} is not "
                f"{size}-byte aligned"
            )

        # r = break on read OR write access.
        self.command(
            f"ba r{size} 0x{address:x}"
        )

    def list_breakpoints(self) -> str:
        return self.command("bl")

    def clear_all_breakpoints(self) -> None:
        self.command("bc *")

    # ------------------------------------------------------------------
    # Memory
    # ------------------------------------------------------------------

    def read_qword(
        self,
        address: int,
    ) -> int:

        output = self.command(
            f"dq 0x{address:x} L1"
        )

        # Typical:
        #
        # 00000091`5555fb90  00000000`00000000
        pattern = re.compile(
            r"^\s*[0-9a-fA-F`]+\s+"
            r"([0-9a-fA-F`]+)",
            re.MULTILINE,
        )

        match = pattern.search(
            output
        )

        if match is None:
            raise DebuggerError(
                f"Could not read qword at "
                f"0x{address:x}:\n"
                f"{output}"
            )

        return self._parse_address(
            match.group(1)
        )

    # ------------------------------------------------------------------
    # Disassembly
    # ------------------------------------------------------------------

    def disassemble_one(
        self,
        address: int,
    ) -> Instruction:

        output = self.command(
            f"u 0x{address:x} L1"
        )

        instruction = (
            self._parse_first_instruction(
                output
            )
        )

        if instruction is None:
            raise DebuggerError(
                f"Could not disassemble "
                f"0x{address:x}:\n"
                f"{output}"
            )

        return instruction

    def disassemble_previous(
        self,
        address: int,
    ) -> Instruction:

        output = self.command(
            f"ub 0x{address:x} L1"
        )

        instructions = (
            self._parse_instructions(
                output
            )
        )

        if not instructions:
            raise DebuggerError(
                f"Could not disassemble before "
                f"0x{address:x}:\n"
                f"{output}"
            )

        return instructions[-1]

    def iter_instructions(
        self,
        address: int,
        max_instructions: int = 16,
    ) -> Iterator[Instruction]:

        current = address

        for _ in range(
            max_instructions
        ):
            instruction = (
                self.disassemble_one(
                    current
                )
            )

            yield instruction

            if instruction.size == 0:
                raise DebuggerError(
                    f"Zero-length instruction at "
                    f"0x{instruction.address:x}"
                )

            current += instruction.size

    # ------------------------------------------------------------------
    # Relative direct JMP decoding
    # ------------------------------------------------------------------

    @staticmethod
    def resolve_direct_jump(
        instruction: Instruction,
    ) -> DirectJump | None:

        raw = instruction.raw_bytes

        if not raw:
            return None

        # JMP rel32
        #
        # E9 xx xx xx xx
        if (
            raw[0] == 0xE9
            and len(raw) >= 5
        ):
            displacement = struct.unpack(
                "<i",
                raw[1:5],
            )[0]

            target = (
                instruction.address
                + 5
                + displacement
            )

            return DirectJump(
                source=instruction.address,
                target=target,
                size=5,
            )

        # JMP rel8
        #
        # EB xx
        if (
            raw[0] == 0xEB
            and len(raw) >= 2
        ):
            displacement = struct.unpack(
                "<b",
                raw[1:2],
            )[0]

            target = (
                instruction.address
                + 2
                + displacement
            )

            return DirectJump(
                source=instruction.address,
                target=target,
                size=2,
            )

        return None

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_address(
        value: str,
    ) -> int:

        return int(
            value.replace(
                "`",
                "",
            ),
            16,
        )

    def _parse_first_instruction(
        self,
        output: str,
    ) -> Instruction | None:

        instructions = (
            self._parse_instructions(
                output
            )
        )

        if not instructions:
            return None

        return instructions[0]

    def _parse_instructions(
        self,
        output: str,
    ) -> list[Instruction]:

        instructions: list[
            Instruction
        ] = []

        for line in output.splitlines():
            match = self._DISASM_RE.match(
                line
            )

            if match is None:
                continue

            (
                address_text,
                bytes_text,
                mnemonic,
                operands,
            ) = match.groups()

            # Must be an even-length hex byte string.
            if len(bytes_text) % 2 != 0:
                continue

            try:
                raw_bytes = bytes.fromhex(
                    bytes_text
                )

            except ValueError:
                continue

            instructions.append(
                Instruction(
                    address=self._parse_address(
                        address_text
                    ),
                    raw_bytes=raw_bytes,
                    mnemonic=mnemonic.lower(),
                    operands=(
                        operands or ""
                    ).strip(),
                    text=line.strip(),
                )
            )

        return instructions

    def get_process_id(self) -> int:
        '''
        Return the PID of the current debuggee process.
        '''


        output = self.command("|")

        # Typical CDB output contains something like:
        #
        # .  0    id: 1a2c    create  name: sample.exe
        #
        pattern = re.compile(
            r"^\s*[\.\#]?\s*\d+\s+"
            r"id:\s*([0-9a-fA-F]+)",
            re.MULTILINE,
        )

        match = pattern.search(output)

        if match is None:
            raise DebuggerError(
                "Could not determine debuggee PID:\n"
                f"{output}"
            )

        return int(
            match.group(1),
            16,
        )