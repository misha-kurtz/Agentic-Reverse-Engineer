# binary-eval/workflows/payload_recovery/runtime_unpack.py

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pefile

from runners.debugger import CdbDebugger, DebuggerError, DirectJump, Instruction, ModuleInfo
from runners.iat import IATAnalysisResult, Thunk
from runners.import_resolver import ResolvedImport
from runners.post_oep_recovery import PostOEPRecovery
from runners.reconstruction import ReconstructionResult


'''
UPX Runtime Unpacking Workflow

Packed entry point: Identify the UPX entry point and verify that the loader
begins with PUSH RBX.

Stack sentinel: Track the saved RBX value using a hardware access breakpoint
to detect when the UPX loader restores the original execution context.

Stub exit detection: Identify the direct JMP transferring execution from
the UPX loader section into the reconstructed executable section.

OEP confirmation: Execute the stub-exit JMP and verify that execution reaches
the recovered original entry point.

Post-OEP recovery: Invoke the shared recovery workflow to dump the unpacked
image, analyze and resolve imports, and reconstruct the executable.


Packed executable entry point
        |
        v
Parse PE headers and section metadata
        |
        v
Launch executable under CDB
        |
        v
Identify loaded image base and packed entry point
        |
        v
Install breakpoint at packed entry point
        |
        v
Verify execution reaches packed entry point
        |
        v
Validate initial PUSH RBX instruction
        |
        v
Record original RSP and RBX
        |
        v
Single-step PUSH RBX
        |
        v
Verify RSP decreases by 8 bytes
        |
        v
Validate saved RBX value on stack
        |
        v
Install hardware access breakpoint on saved RBX
        |
        v
Monitor UPX loader execution
        |
        v
Detect matching POP RBX
        |
        v
Verify original RSP and RBX are restored
        |
        v
Locate direct stub-exit JMP
        |
        v
Verify JMP originates in UPX loader section
        |
        v
Verify JMP targets a different executable section
        |
        v
Install breakpoint at stub-exit JMP
        |
        v
Confirm execution reaches stub-exit JMP
        |
        v
Validate live JMP instruction and destination
        |
        v
Single-step stub-exit JMP
        |
        v
Confirm execution transfers to recovered OEP
        |
        v
Verify OEP resides in reconstructed section
        |
        v
Calculate OEP RVA from loaded image base
        |
        v
Invoke shared PostOEPRecovery workflow
        |
        v
Dump unpacked executable image from memory
        |
        v
Analyze and resolve reconstructed imports
        |
        v
Reconstruct executable on disk
        |
        v
Return recovered OEP, IAT, and reconstruction metadata

'''

class RuntimeUnpackError(RuntimeError):
    pass


@dataclass(frozen=True)
class SectionRange:
    name: str
    rva: int
    virtual_size: int
    characteristics: int
    start_va: int
    end_va: int

    def contains(self, address: int) -> bool:
        return self.start_va <= address < self.end_va

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)


@dataclass(frozen=True)
class UnpackResult:
    input_path: Path
    pid: int
    image_base: int

    packed_entry_va: int
    packed_entry_rva: int

    entry_rsp: int
    saved_rbx_slot: int

    stub_jump_va: int
    stub_jump_rva: int

    oep_va: int
    oep_rva: int

    source_section: str
    destination_section: str

    iat_start_va: int
    iat_size: int
    iat_valid_thunks: int
    iat_invalid_thunks: int

    iat_thunks: tuple[Thunk, ...]
    iat_analysis: IATAnalysisResult
    resolved_imports: tuple[ResolvedImport, ...]
    loaded_modules: tuple[ModuleInfo, ...]

    dump_path: Path
    reconstructed_path: Path | None
    reconstruction: ReconstructionResult | None

    @property
    def iat_rva(self) -> int:
        return self.iat_start_va - self.image_base


class RuntimeUnpacker:
    '''
    Deterministic runtime UPX recovery.

    Workflow:
        packed EP
            -> push rbx
            -> watch saved RBX stack slot
            -> matching pop rbx
            -> direct JMP from stub into reconstructed section
            -> OEP
            -> shared post-OEP recovery
    '''

    def __init__(
        self,
        debugger: CdbDebugger,
        max_stack_watch_events: int = 8,
        max_post_restore_instructions: int = 16,
    ):
        self.debugger = debugger
        self.max_stack_watch_events = max_stack_watch_events
        self.max_post_restore_instructions = max_post_restore_instructions

    # ------------------------------------------------------------------
    # Public workflow
    # ------------------------------------------------------------------

    def run(self, executable: Path | str) -> UnpackResult:
        executable = Path(executable)
        pe_info = self._parse_pe(executable)

        self.debugger.launch(executable)

        try:
            module = self.debugger.get_module(executable.name)
            pid = self.debugger.get_process_id()

            image_base = module.base
            image_end = module.end

            packed_entry_rva = pe_info['entry_rva']
            packed_entry_va = image_base + packed_entry_rva

            sections = self._build_runtime_sections(pe_info, image_base)
            stub = self._find_section_containing_va(sections, packed_entry_va)

            if not stub.executable:
                raise RuntimeUnpackError('Packed entry point is not located inside an executable section')

            # 1. Run to packed entry point.

            self.debugger.set_breakpoint(packed_entry_va)
            self.debugger.continue_execution()

            rip = self.debugger.get_register('rip')

            if rip != packed_entry_va:
                raise RuntimeUnpackError(
                    f'Did not stop at packed entry point: '
                    f'expected 0x{packed_entry_va:X}, got 0x{rip:X}'
                )

            # 2. Verify packed EP begins with push rbx.

            entry_instruction = self.debugger.disassemble_one(packed_entry_va)
            self._require_push_rbx(entry_instruction)

            # 3. Record original RSP/RBX.

            registers = self.debugger.get_registers('rsp', 'rbx')
            entry_rsp = registers['rsp']
            entry_rbx = registers['rbx']

            # The software entry breakpoint is no longer needed.

            self.debugger.clear_all_breakpoints()

            # 4. Execute push rbx.

            self.debugger.step_into()

            new_rsp = self.debugger.get_register('rsp')
            expected_rsp = entry_rsp - 8

            if new_rsp != expected_rsp:
                raise RuntimeUnpackError(
                    f'push rbx did not produce expected RSP: '
                    f'expected 0x{expected_rsp:X}, got 0x{new_rsp:X}'
                )

            saved_rbx_slot = new_rsp

            # Verify the qword at [new RSP] contains the pushed RBX.

            saved_value = self.debugger.read_qword(saved_rbx_slot)

            if saved_value != entry_rbx:
                raise RuntimeUnpackError(
                    f'Saved RBX stack value does not match entry RBX: '
                    f'expected 0x{entry_rbx:X}, got 0x{saved_value:X}'
                )

            # 5. Hardware read/write breakpoint on saved RBX qword.

            self.debugger.set_access_breakpoint(address=saved_rbx_slot, size=8)

            # 6. Identify matching outer pop rbx.

            restore_rip = self._wait_for_outer_rbx_restore(entry_rsp, entry_rbx)

            # Remove the saved-RBX hardware watchpoint.

            self.debugger.clear_all_breakpoints()

            # 7. Locate the direct JMP into the reconstructed section.

            jump, destination = self._find_stub_exit_jump(
                start_va=restore_rip,
                stub=stub,
                sections=sections,
            )

            # 8. Break directly on the stub-exit JMP.

            self.debugger.set_breakpoint(jump.source)
            self.debugger.continue_execution()

            current_rip = self.debugger.get_register('rip')

            print(f'[debug] Expected stub-exit JMP: 0x{jump.source:X}')
            print(f'[debug] Current RIP after continue: 0x{current_rip:X}')

            for instruction in self.debugger.iter_instructions(current_rip, max_instructions=8):
                print(f'[debug] {instruction.text}')

            if current_rip != jump.source:
                raise RuntimeUnpackError(
                    f'Did not stop at stub exit JMP: '
                    f'expected 0x{jump.source:X}, got 0x{current_rip:X}'
                )

            # 9. Validate the live JMP instruction.

            live_jump_instruction = self.debugger.disassemble_one(current_rip)
            live_jump = self.debugger.resolve_direct_jump(live_jump_instruction)

            if live_jump is None:
                raise RuntimeUnpackError(f'Instruction at 0x{current_rip:X} is not a direct JMP')

            if live_jump.target != jump.target:
                raise RuntimeUnpackError(
                    f'JMP target changed unexpectedly: '
                    f'expected 0x{jump.target:X}, got 0x{live_jump.target:X}'
                )

            # 10. Execute exactly the stub-exit JMP.

            self.debugger.step_into()
            oep_va = self.debugger.get_register('rip')

            # 11. Verify the debugger reached the expected OEP.

            if oep_va != jump.target:
                raise RuntimeUnpackError(
                    f'JMP did not land on expected OEP: '
                    f'expected 0x{jump.target:X}, got 0x{oep_va:X}'
                )

            if not destination.contains(oep_va):
                raise RuntimeUnpackError(
                    f'OEP does not lie inside reconstructed section '
                    f'{destination.name}: 0x{oep_va:X}'
                )

            # Calculate RVAs relative to the loaded image base.

            oep_rva = oep_va - image_base
            stub_jump_rva = jump.source - image_base

            print(f'[upx] Recovered OEP VA: 0x{oep_va:X}')
            print(f'[upx] Recovered OEP RVA: 0x{oep_rva:X}')
            print(f'[upx] Stub-exit JMP VA: 0x{jump.source:X}')
            print(f'[upx] Stub-exit JMP RVA: 0x{stub_jump_rva:X}')

                        # ----------------------------------------------------------
            # 12. Shared post-OEP recovery
            # ----------------------------------------------------------

            image_size = image_end - image_base

            dump_dir = Path.cwd() / "dumps"
            dump_dir.mkdir(parents=True, exist_ok=True)

            dump_path = dump_dir / f"{executable.stem}_memory.bin"
            reconstructed_path = dump_dir / f"{executable.stem}_reconstructed.exe"

            print("\n=== UPX POST-OEP RECOVERY ===")
            print(f"[upx] Image base: 0x{image_base:X}")
            print(f"[upx] Image size: 0x{image_size:X}")
            print(f"[upx] OEP VA: 0x{oep_va:X}")
            print(f"[upx] OEP RVA: 0x{oep_rva:X}")

            post_oep = PostOEPRecovery(self.debugger)

            recovery = post_oep.run(
                image_base=image_base,
                image_size=image_size,
                oep_rva=oep_rva,
                dump_path=dump_path,
                reconstructed_path=reconstructed_path,
                packed_entry_rva=packed_entry_rva,
                stub_jump_rva=stub_jump_rva,
            )

            # ----------------------------------------------------------
            # 13. Return complete UPX recovery metadata
            # ----------------------------------------------------------

            return UnpackResult(
                input_path=executable,
                pid=pid,
                image_base=image_base,
                packed_entry_va=packed_entry_va,
                packed_entry_rva=packed_entry_rva,
                entry_rsp=entry_rsp,
                saved_rbx_slot=saved_rbx_slot,
                stub_jump_va=jump.source,
                stub_jump_rva=stub_jump_rva,
                oep_va=oep_va,
                oep_rva=oep_rva,
                source_section=stub.name,
                destination_section=destination.name,
                iat_start_va=recovery.iat_start_va,
                iat_size=recovery.iat_size,
                iat_valid_thunks=recovery.iat_valid_thunks,
                iat_invalid_thunks=recovery.iat_invalid_thunks,
                iat_thunks=recovery.iat_thunks,
                iat_analysis=recovery.iat_analysis,
                resolved_imports=recovery.resolved_imports,
                loaded_modules=recovery.loaded_modules,
                dump_path=recovery.dump_path,
                reconstructed_path=recovery.reconstructed_path,
                reconstruction=recovery.reconstruction,
            )

        except Exception:
            self.debugger.close()
            raise

    # ------------------------------------------------------------------
    # Sentinel restoration
    # ------------------------------------------------------------------

    def _wait_for_outer_rbx_restore(self, entry_rsp: int, entry_rbx: int) -> int:
        for _ in range(self.max_stack_watch_events):
            self.debugger.continue_execution()

            rip = self.debugger.get_register('rip')
            rsp = self.debugger.get_register('rsp')
            rbx = self.debugger.get_register('rbx')

            try:
                previous = self.debugger.disassemble_previous(rip)
            except DebuggerError:
                previous = None

            # Hardware data breakpoints on x86/x64 fire after
            # the memory-accessing instruction.
            #
            # After the matching pop rbx:
            #   RIP = next instruction
            #   RSP = original entry RSP
            #   RBX = original entry RBX

            if (
                previous is not None
                and self._is_pop_rbx(previous)
                and rsp == entry_rsp
                and rbx == entry_rbx
            ):
                return rip

            # Another instruction accessed the sentinel.
            # Continue watching.

        raise RuntimeUnpackError(
            'Saved RBX slot was accessed, but no matching '
            'outer pop rbx was identified'
        )

    # ------------------------------------------------------------------
    # Locate stub-exit JMP
    # ------------------------------------------------------------------

    def _find_stub_exit_jump(
        self,
        start_va: int,
        stub: SectionRange,
        sections: list[SectionRange],
    ) -> tuple[DirectJump, SectionRange]:
        '''
        Requirements:
            1. Direct JMP.
            2. Source is in the packed-entry-point section.
            3. Target is in a different section.
            4. Target section is executable.
        '''

        for instruction in self.debugger.iter_instructions(start_va, max_instructions=self.max_post_restore_instructions):
            jump = self.debugger.resolve_direct_jump(instruction)

            if jump is None:
                continue

            if not stub.contains(jump.source):
                continue

            destination = self._find_section_containing_va(sections, jump.target, required=False)

            if destination is None:
                continue

            if destination.rva == stub.rva:
                continue

            if not destination.executable:
                continue

            return jump, destination

        raise RuntimeUnpackError(
            'Could not locate direct inter-section '
            'stub-exit JMP after the RBX restore'
        )

    # ------------------------------------------------------------------
    # Instruction validation
    # ------------------------------------------------------------------

    @staticmethod
    def _require_push_rbx(instruction: Instruction) -> None:
        operands = instruction.operands.lower().replace(' ', '')

        if instruction.mnemonic != 'push' or operands != 'rbx':
            raise RuntimeUnpackError(
                'Packed entry point does not begin with '
                f"'push rbx': {instruction.text}"
            )

    @staticmethod
    def _is_pop_rbx(instruction: Instruction) -> bool:
        operands = instruction.operands.lower().replace(' ', '')
        return instruction.mnemonic == 'pop' and operands == 'rbx'

    # ------------------------------------------------------------------
    # PE parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_pe(path: Path) -> dict:
        pe = pefile.PE(str(path), fast_load=True)

        try:
            sections = []

            for section in pe.sections:
                name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
                virtual_size = section.Misc_VirtualSize or section.SizeOfRawData

                sections.append(
                    {
                        'name': name,
                        'rva': section.VirtualAddress,
                        'virtual_size': virtual_size,
                        'characteristics': section.Characteristics,
                    }
                )

            return {
                'entry_rva': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'section_alignment': pe.OPTIONAL_HEADER.SectionAlignment,
                'sections': sections,
            }

        finally:
            pe.close()

    def _build_runtime_sections(self, pe_info: dict, image_base: int) -> list[SectionRange]:
        alignment = pe_info['section_alignment']
        result = []

        for section in pe_info['sections']:
            size = self._align_up(section['virtual_size'], alignment)
            start = image_base + section['rva']

            result.append(
                SectionRange(
                    name=section['name'],
                    rva=section['rva'],
                    virtual_size=size,
                    characteristics=section['characteristics'],
                    start_va=start,
                    end_va=start + size,
                )
            )

        return result

    @staticmethod
    def _find_section_containing_va(
        sections: list[SectionRange],
        address: int,
        required: bool = True,
    ) -> SectionRange | None:
        for section in sections:
            if section.contains(address):
                return section

        if required:
            raise RuntimeUnpackError(f'Address 0x{address:X} is not contained in any PE section')

        return None

    @staticmethod
    def _align_up(value: int, alignment: int) -> int:
        if alignment == 0:
            return value

        return (value + alignment - 1) & ~(alignment - 1)