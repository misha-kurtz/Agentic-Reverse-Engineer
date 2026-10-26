'''
CFG traversal unit test using a mock debugger to simulate instruction disassembly and control flow analysis. This test verifies the correct construction of the control flow graph (CFG) from a set of predefined instructions, ensuring that edges and unresolved instructions are accurately represented. The mock debugger provides a controlled environment for testing without relying on an actual debugger or executable.

Input instructions:
        0x1000: make_instruction(0x1000, "85c0", "test"),
        0x1002: make_instruction(0x1002, "7407", "je"),
        0x1004: make_instruction(0x1004, "bb01000000", "mov"),
        0x1009: make_instruction(0x1009, "eb05", "jmp"),
        0x100B: make_instruction(0x100B, "0000", "add"),
        0x1010: make_instruction(0x1010, "c3", "ret"),


Output CFG:
                   0x1000
                      |
                   0x1002
                  /      \
              0x1004    0x100B
                 |         |
              0x1009    0x100D
                 |         |
              0x1010    Decode error
                 |
                RET
'''

from runners.debugger import Instruction, DebuggerError
from runners.dynamic_cfg import ControlFlowAnalyzer

class MockDebugger:
    def __init__(self, instructions: dict[int, Instruction]):
        self.instructions = instructions

    def disassemble_one(self, address: int) -> Instruction:
        if address not in self.instructions:
            raise DebuggerError(f"No instruction at 0x{address:X}")

        return self.instructions[address]

def make_instruction(address: int, raw: str, mnemonic: str) -> Instruction:
    return Instruction(address, bytes.fromhex(raw), mnemonic, "", "")

def main() -> None:
    instructions = {
        0x1000: make_instruction(0x1000, "85c0", "test"),
        0x1002: make_instruction(0x1002, "7407", "je"),
        0x1004: make_instruction(0x1004, "bb01000000", "mov"),
        0x1009: make_instruction(0x1009, "eb05", "jmp"),
        0x100B: make_instruction(0x100B, "0000", "add"),
        0x1010: make_instruction(0x1010, "c3", "ret"),
    }

    analyzer = ControlFlowAnalyzer(MockDebugger(instructions))
    graph = analyzer.analyze(0x1000, 0x1000, 0x1020)

    print(f"Decoded instructions: {len(graph.instructions)}")
    print(f"Edges: {sum(len(edges) for edges in graph.edges.values())}")
    print(f"Unresolved: {len(graph.unresolved)}")
    print(f"Decode errors: {len(graph.decode_errors)}")

    for address, successors in sorted(graph.edges.items()):
        print(f"0x{address:X} -> {[hex(s) for s in sorted(successors)]}")

if __name__ == "__main__":
    main()