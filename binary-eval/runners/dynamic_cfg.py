from dataclasses import dataclass
import struct

from runners.debugger import Instruction

@dataclass(frozen=True)
class ControlFlowInfo:
    address: int
    fallthrough: int | None
    branch_target: int | None
    kind: str

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