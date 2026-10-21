'''
CFG Traversal Regression Test
=========================================================================
| Test                        | Expected behavior                        |
| --------------------------- | ---------------------------------------- |
| Backward conditional jump   | Visits each instruction once             |
| Infinite unconditional loop | Terminates through visited tracking      |
| Jump over embedded data     | Does not decode skipped bytes            |
| Indirect jump               | Records unresolved destination           |
| Out-of-bounds branch        | Records unresolved destination           |
| Instruction limit           | Stops without exceeding configured limit |

'''

from runners.debugger import Instruction, DebuggerError
from runners.dynamic_cfg import ControlFlowAnalyzer


class MockDebugger:
    def __init__(self, instructions: dict[int, Instruction]):
        self.instructions = instructions
        self.calls = []

    def disassemble_one(self, address: int) -> Instruction:
        self.calls.append(address)

        if address not in self.instructions:
            raise DebuggerError(f"No instruction at 0x{address:X}")

        return self.instructions[address]


def ins(address: int, raw: str, mnemonic: str, operands: str = "") -> Instruction:
    return Instruction(address, bytes.fromhex(raw), mnemonic, operands, "")


def analyze(instructions: dict, entry: int = 0x1000, end: int = 0x1100, limit: int = 100):
    debugger = MockDebugger(instructions)
    graph = ControlFlowAnalyzer(debugger, max_instructions=limit).analyze(entry, entry, end)
    return graph, debugger


def test_backward_conditional_jump():
    instructions = {
        0x1000: ins(0x1000, "90", "nop"),
        0x1001: ins(0x1001, "75fd", "jne"),
        0x1003: ins(0x1003, "c3", "ret"),
    }

    graph, debugger = analyze(instructions)

    assert set(graph.instructions) == {0x1000, 0x1001, 0x1003}
    assert graph.edges[0x1001] == {0x1000, 0x1003}
    assert len(debugger.calls) == len(set(debugger.calls))
    assert not graph.decode_errors

    print("[PASS] Backward conditional jump: each instruction visited once")


def test_infinite_unconditional_loop():
    instructions = {
        0x1000: ins(0x1000, "ebfe", "jmp"),
    }

    graph, debugger = analyze(instructions)

    assert set(graph.instructions) == {0x1000}
    assert graph.edges[0x1000] == {0x1000}
    assert debugger.calls == [0x1000]
    assert not graph.decode_errors

    print("[PASS] Infinite unconditional loop: traversal terminates")


def test_jump_over_embedded_data():
    instructions = {
        0x1000: ins(0x1000, "eb10", "jmp"),
        0x1012: ins(0x1012, "c3", "ret"),
    }

    graph, debugger = analyze(instructions)

    assert set(graph.instructions) == {0x1000, 0x1012}
    assert graph.edges[0x1000] == {0x1012}
    assert debugger.calls == [0x1000, 0x1012]
    assert not graph.decode_errors

    print("[PASS] Embedded data: skipped bytes never disassembled")


def test_indirect_jump():
    instructions = {
        0x1000: ins(0x1000, "ffe0", "jmp", "rax"),
    }

    graph, debugger = analyze(instructions)

    assert set(graph.instructions) == {0x1000}
    assert graph.edges[0x1000] == set()
    assert 0x1000 in graph.unresolved
    assert not graph.decode_errors

    print("[PASS] Indirect jump: unresolved destination recorded")


def test_out_of_bounds_branch():
    instructions = {
        0x1000: ins(0x1000, "e9fb000000", "jmp"),
    }

    graph, debugger = analyze(instructions, end=0x1050)

    assert set(graph.instructions) == {0x1000}
    assert graph.edges[0x1000] == set()
    assert 0x1000 in graph.unresolved
    assert not graph.decode_errors

    print("[PASS] Out-of-bounds branch: unresolved destination recorded")


def test_instruction_limit():
    instructions = {
        0x1000 + i: ins(0x1000 + i, "90", "nop")
        for i in range(20)
    }

    graph, debugger = analyze(instructions, limit=5)

    assert len(graph.instructions) == 5
    assert len(debugger.calls) == 5
    assert set(graph.instructions) == set(range(0x1000, 0x1005))
    assert 0x1005 in graph.unresolved

    print("[PASS] Instruction limit: traversal stops at configured maximum")


def main():
    tests = [
        test_backward_conditional_jump,
        test_infinite_unconditional_loop,
        test_jump_over_embedded_data,
        test_indirect_jump,
        test_out_of_bounds_branch,
        test_instruction_limit,
    ]

    print("=" * 70)
    print("DYNAMIC CFG REGRESSION TEST")
    print("=" * 70)

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as exc:
            failed += 1
            print(f"[FAIL] {test.__name__}: {type(exc).__name__}: {exc}")

    print(f"\n{'=' * 70}")
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total:  {len(tests)}")

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()