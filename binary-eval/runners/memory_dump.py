# binary-eval/runners/memory_dump.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from runners.debugger import CdbDebugger


class MemoryDumpError(RuntimeError):
    pass


@dataclass(frozen=True)
class MemoryDumpResult:
    path: Path

    start_va: int
    end_va: int
    size: int

    @property
    def actual_size(self) -> int:
        return self.path.stat().st_size


class MemoryDumper:
    '''
    Dump a contiguous region from the live debuggee.

    This stage intentionally performs no PE reconstruction.
    It captures the mapped image exactly as it exists in memory
    at the confirmed OEP.
    '''

    def __init__(
        self,
        debugger: CdbDebugger,
    ):
        self.debugger = debugger

    def dump_image(
        self,
        output_path: Path | str,
        start_va: int,
        end_va: int,
    ) -> MemoryDumpResult:

        output_path = Path(output_path)

        if end_va <= start_va:
            raise ValueError(
                "end_va must be greater than start_va"
            )

        expected_size = end_va - start_va

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if output_path.exists():
            output_path.unlink()

        self.debugger.write_memory(
            output_path=output_path,
            start_va=start_va,
            end_va=end_va,
        )

        if not output_path.exists():
            raise MemoryDumpError(
                f"Memory dump was not created: "
                f"{output_path}"
            )

        actual_size = output_path.stat().st_size

        if actual_size != expected_size:
            raise MemoryDumpError(
                "Memory dump size mismatch: "
                f"expected 0x{expected_size:X} "
                f"({expected_size} bytes), "
                f"got 0x{actual_size:X} "
                f"({actual_size} bytes)"
            )

        return MemoryDumpResult(
            path=output_path,
            start_va=start_va,
            end_va=end_va,
            size=expected_size,
        )