'''
Dynamic CFG Integration Test with ConsoleDbg and Test Executable cfg-test.exe
'''

import re
import sys
from pathlib import Path

from runners.debugger import CdbDebugger, DebuggerError
from runners.dynamic_cfg import ControlFlowAnalyzer


EXECUTABLE = Path("cfg-test.exe").resolve()
FUNCTION = "cfg-test!calculate"
MAX_INSTRUCTIONS = 200
FUNCTION_WINDOW = 0x200


CDB_PATH = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")

def create_debugger(executable: Path) -> CdbDebugger:
    debugger = CdbDebugger(CDB_PATH, command_timeout=30.0)
    debugger.launch(executable)
    return debugger

def resolve_symbol(debugger: CdbDebugger, symbol: str) -> int:
    output = debugger.command(f"x {symbol}")

    pattern = re.compile(r"^\s*([0-9a-fA-F`]+)\s+", re.MULTILINE)
    match = pattern.search(output)

    if not match:
        raise DebuggerError(f"Unable to resolve symbol {symbol}:\n{output}")

    return int(match.group(1).replace("`", ""), 16)


def validate_instructions(debugger: CdbDebugger, graph) -> None:
    for address, instruction in graph.instructions.items():
        assert instruction.address == address
        assert 1 <= instruction.size <= 15

        actual = debugger.read_instruction_bytes(address, instruction.size)
        assert actual == instruction.raw_bytes, (
            f"Instruction bytes mismatch at 0x{address:X}: "
            f"{instruction.raw_bytes.hex()} != {actual.hex()}"
        )


def validate_edges(graph, start_va: int, end_va: int) -> None:
    for source, successors in graph.edges.items():
        assert source in graph.instructions

        for target in successors:
            assert start_va <= target < end_va

            if not graph.truncated:
                assert target in graph.instructions or target in graph.decode_errors, (
                    f"Unaccounted CFG edge: 0x{source:X} -> 0x{target:X}"
                )


def print_graph(graph) -> None:
    print("\n=== CFG SUMMARY ===")
    print(f"Entry:                0x{graph.entry_va:X}")
    print(f"Decoded instructions: {len(graph.instructions)}")
    print(f"Edges:                {sum(len(v) for v in graph.edges.values())}")
    print(f"Unresolved:           {len(graph.unresolved)}")
    print(f"Decode errors:        {len(graph.decode_errors)}")
    print(f"Pending:              {len(graph.pending)}")
    print(f"Truncated:            {graph.truncated}")

    print("\n=== CONTROL-FLOW EDGES ===")

    for address, successors in sorted(graph.edges.items()):
        instruction = graph.instructions[address]
        targets = ", ".join(f"0x{target:X}" for target in sorted(successors))
        print(f"0x{address:X}: {instruction.mnemonic:<8} -> [{targets}]")

    if graph.decode_errors:
        print("\n=== DECODE ERRORS ===")

        for address, error in sorted(graph.decode_errors.items()):
            print(f"0x{address:X}: {error}")


def main() -> None:
    if not EXECUTABLE.exists():
        raise FileNotFoundError(f"Executable not found: {EXECUTABLE}")

    debugger = create_debugger(EXECUTABLE)

    try:
        debugger.command(".sympath+ .")
        debugger.command(".reload /f")
        entry_va = resolve_symbol(debugger, FUNCTION)
        start_va = entry_va
        end_va = entry_va + FUNCTION_WINDOW

        print(f"[INFO] Executable: {EXECUTABLE}")
        print(f"[INFO] Function:   {FUNCTION}")
        print(f"[INFO] Entry VA:   0x{entry_va:X}")
        print(f"[INFO] Bounds:     0x{start_va:X} - 0x{end_va:X}")

        analyzer = ControlFlowAnalyzer(debugger, max_instructions=MAX_INSTRUCTIONS)
        graph = analyzer.analyze(entry_va, start_va, end_va)

        validate_instructions(debugger, graph)
        validate_edges(graph, start_va, end_va)

        assert graph.instructions, "No instructions decoded"
        assert entry_va in graph.instructions, "Entry instruction missing"

        print_graph(graph)
        print("\n[PASS] Live CDB CFG integration test")

    finally:
        debugger.close()


if __name__ == "__main__":
    main()