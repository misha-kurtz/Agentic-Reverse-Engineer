from dataclasses import dataclass
from collections import deque
import struct

from runners.debugger import Instruction, CdbDebugger, DebuggerError

@dataclass(frozen=True)
class ControlFlowInfo:
    address: int
    fallthrough: int | None
    branch_target: int | None
    kind: str

@dataclass
class ControlFlowGraph:
    entry_va: int
    instructions: dict[int, Instruction]
    edges: dict[int, set[int]]
    unresolved: set[int]
    decode_errors: dict[int, str]

def classify_control_flow(instruction: Instruction) -> ControlFlowInfo:
    mnemonic = instruction.mnemonic.lower()
    next_va = instruction.address + instruction.size
    target = resolve_branch_target(instruction)

    if mnemonic.startswith("ret"):
        return ControlFlowInfo(instruction.address, None, None, "return")

    if mnemonic == "jmp":
        return ControlFlowInfo(instruction.address, None, target, "unconditional_jump")

    if mnemonic.startswith("j") or mnemonic in ("loop", "loope", "loopne", "jrcxz"):
        return ControlFlowInfo(instruction.address, next_va, target, "conditional_jump")

    if mnemonic == "call":
        return ControlFlowInfo(instruction.address, next_va, target, "call")

    if mnemonic in ("int", "int3", "ud2", "hlt"):
        return ControlFlowInfo(instruction.address, None, None, "terminal")

    return ControlFlowInfo(instruction.address, next_va, None, "sequential")

def resolve_branch_target(instruction: Instruction) -> int | None:
    raw = instruction.raw_bytes
    address = instruction.address

    if not raw:
        return None

    opcode = raw[0]

    if opcode in (0xE8, 0xE9) and len(raw) >= 5:
        displacement = struct.unpack("<i", raw[1:5])[0]
        return address + 5 + displacement

    if opcode == 0xEB and len(raw) >= 2:
        displacement = struct.unpack("<b", raw[1:2])[0]
        return address + 2 + displacement

    if 0x70 <= opcode <= 0x7F and len(raw) >= 2:
        displacement = struct.unpack("<b", raw[1:2])[0]
        return address + 2 + displacement

    if len(raw) >= 6 and opcode == 0x0F and 0x80 <= raw[1] <= 0x8F:
        displacement = struct.unpack("<i", raw[2:6])[0]
        return address + 6 + displacement

    return None

class ControlFlowAnalyzer:
    def __init__(self, debugger: CdbDebugger, max_instructions: int = 1000):
        self.debugger = debugger
        self.max_instructions = max_instructions

    def analyze(self, entry_va: int, start_va: int, end_va: int) -> ControlFlowGraph:
        if not start_va <= entry_va < end_va:
            raise ValueError("Entry address must be within analysis bounds")

        graph = ControlFlowGraph(
            entry_va=entry_va,
            instructions={},
            edges={},
            unresolved=set(),
            decode_errors={}
        )

        worklist = deque([entry_va])
        visited = set()

        attempts = 0
        max_attempts = self.max_instructions * 2

        while worklist and len(graph.instructions) < self.max_instructions and attempts < max_attempts:
            address = worklist.popleft()
            
            if address in visited:
                continue

            visited.add(address)
            attempts += 1

            if not start_va <= address < end_va:
                graph.unresolved.add(address)
                continue

            try:
                instruction = self.debugger.disassemble_one(address)
            except DebuggerError as exc:
                graph.decode_errors[address] = str(exc)
                continue

            if address + instruction.size > end_va:
                graph.unresolved.add(address)
                continue

            graph.instructions[address] = instruction
            flow = classify_control_flow(instruction)
            graph.edges[address] = set()

            if flow.kind == "return" or flow.kind == "terminal":
                continue

            if flow.kind == "unconditional_jump":
                successors = [flow.branch_target]
            elif flow.kind == "conditional_jump":
                successors = [flow.fallthrough, flow.branch_target]
            else:
                successors = [flow.fallthrough]

            for successor in successors:
                if successor is None:
                    graph.unresolved.add(address)
                    continue

                if not start_va <= successor < end_va:
                    graph.unresolved.add(address)
                    continue

                graph.edges[address].add(successor)

                if successor not in visited:
                    worklist.append(successor)

        if worklist:
            graph.unresolved.update(worklist)

        return graph