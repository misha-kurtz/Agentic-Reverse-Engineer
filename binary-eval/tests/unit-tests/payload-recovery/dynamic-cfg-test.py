from runners.debugger import Instruction
from runners.dynamic_cfg import classify_control_flow

TEST_CASES = [
    (0x1000, "7405", "je", 0x1007),
    (0x1000, "7505", "jne", 0x1007),
    (0x1000, "eb05", "jmp", 0x1007),
    (0x1000, "e905000000", "jmp", 0x100A),
    (0x1000, "e805000000", "call", 0x100A),
    (0x1000, "0f8505000000", "jne", 0x100B),
]

def main() -> None:
    for address, hex_bytes, mnemonic, expected in TEST_CASES:
        raw = bytes.fromhex(hex_bytes)
        instruction = Instruction(address, raw, mnemonic, "", "")
        flow = classify_control_flow(instruction)

        assert flow.branch_target == expected, (
            f"{mnemonic}: expected 0x{expected:X}, got {flow.branch_target}"
        )

        print(f"[PASS] {mnemonic.upper():5} 0x{address:X} -> 0x{flow.branch_target:X}")

    print(f"\n[PASS] All {len(TEST_CASES)} branch-resolution tests passed")

if __name__ == "__main__":
    main()