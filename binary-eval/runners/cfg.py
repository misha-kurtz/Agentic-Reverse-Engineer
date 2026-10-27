# binary-eval/runners/cfg.py

'''
Control-Flow-Aware Disassembly and CFG Reconstruction

Purpose:
    Analyze the decrypted payload's executable code using debugger-backed
    disassembly and control-flow traversal rather than linear disassembly.

    Starting from a known entry address, recursively discover reachable
    instructions, identify control-flow transitions, and construct a
    Control Flow Graph (CFG) within specified memory boundaries.

Responsibilities:
    1. Receive the entry address and executable memory boundaries.
    2. Initialize a worklist of instruction addresses to analyze.
    3. Disassemble individual instructions using the CDB debugger.
    4. Classify instructions by their control-flow behavior.
    5. Resolve supported direct branch targets from instruction bytes.
    6. Identify sequential, conditional, and unconditional transitions.
    7. Track fallthrough addresses and branch destinations.
    8. Construct CFG edges between reachable instructions.
    9. Avoid repeatedly processing previously visited addresses.
    10. Record unresolved branches and out-of-bounds destinations.
    11. Record debugger disassembly errors.
    12. Enforce instruction and analysis-attempt limits.
    13. Preserve pending addresses when CFG traversal is truncated.
    14. Return the discovered instructions and control-flow metadata.

Input:
    - Active CDB debugger session.
    - Entry virtual address for control-flow analysis.
    - Start and end virtual addresses defining the analysis region.
    - Maximum instruction count.

Output:
    - ControlFlowGraph containing discovered instructions and CFG edges.
    - Unresolved control-flow references.
    - Instruction decoding errors.
    - Pending instruction addresses when traversal is truncated.
    - DisassemblyResult containing collected instructions and metadata.

Workflow:
    Receive entry VA and analysis boundaries
        |
        v
    Initialize CFG and instruction worklist
        |
        v
    Select next unvisited instruction address
        |
        v
    Validate address against analysis boundaries
        |
        v
    Disassemble instruction using CDB
        |
        v
    Classify instruction control flow
        |
        v
    Identify instruction successors
        |
        +------------------------------+
        |                              |
        v                              v
    Sequential / Call             Jump / Branch
        |                              |
        v                              v
    Follow fallthrough            Resolve direct target
        |                              |
        +---------------+--------------+
                        |
                        v
    Validate successor addresses
                        |
                        v
    Record CFG edges and unresolved references
                        |
                        v
    Add unvisited successors to worklist
                        |
                        v
    Continue until worklist exhausted or limits reached
                        |
                        v
    Record pending addresses if truncated
                        |
                        v
    Return ControlFlowGraph
                        |
                        v
    Collect instructions into DisassemblyResult

This module performs control-flow-aware instruction discovery using
the debugger's disassembly capabilities.

Unlike linear disassembly, it follows discovered control-flow paths
instead of decoding every consecutive byte in the analysis region.

Supported direct relative branches are resolved from instruction bytes.
Indirect branch targets are not resolved by the current implementation.

Call instructions follow their fallthrough address; called function
targets are not recursively traversed.

This module constructs a static CFG from debugger-disassembled code.
It does not trace actual runtime branch execution, modify instructions,
or reconstruct the PE executable.
'''

from dataclasses import dataclass,field
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
    truncated: bool = False
    pending: set[int] = field(default_factory=set)

@dataclass(frozen=True)
class DisassemblyResult:
    instructions: tuple[Instruction, ...]
    unresolved: frozenset[int]
    decode_errors: dict[int, str]
    pending: frozenset[int]
    truncated: bool

def classify_control_flow(instruction: Instruction) -> ControlFlowInfo:
    mnemonic = instruction.mnemonic.lower()
    next_va = instruction.address + instruction.size
    target = resolve_branch_target(instruction)

    if mnemonic.startswith("ret"):
        return ControlFlowInfo(instruction.address, None, None, "return")

    if mnemonic == "jmp":
        return ControlFlowInfo(instruction.address, None, target, "unconditional_jump")

    if mnemonic.startswith("j") or mnemonic.startswith("loop"):
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

    if 0xE0 <= opcode <= 0xE3 and len(raw) >= 2:
        displacement = struct.unpack("<b", raw[1:2])[0]
        return address + 2 + displacement

    return None

def collect_cfg_instructions(graph: ControlFlowGraph) -> DisassemblyResult:
    instructions = tuple(
        graph.instructions[address]
        for address in sorted(graph.instructions)
    )

    return DisassemblyResult(
        instructions=instructions,
        unresolved=frozenset(graph.unresolved),
        decode_errors=dict(graph.decode_errors),
        pending=frozenset(graph.pending),
        truncated=graph.truncated,
    )

class ControlFlowAnalyzer:
    def __init__(self, debugger: CdbDebugger, max_instructions: int = 1000):
        if max_instructions < 1:
            raise ValueError("max_instructions must be positive")

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
            graph.truncated = True
            graph.pending.update(worklist)

        return graph


