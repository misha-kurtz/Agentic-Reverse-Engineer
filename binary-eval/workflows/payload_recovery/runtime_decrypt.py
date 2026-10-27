# binary-eval/workflows/payload_recovery/runtime_decrypt.py

'''
Hyperion Runtime Decryption Workflow

Payload recovery: Confirm Hyperion has decrypted the original PE into the intermediate buffer.

OEP discovery: Extract the candidate OEP RVA from the decrypted PE headers.

Runtime confirmation: Verify that execution actually transfers to the recovered OEP and that 
the final mapped image is ready for dumping.
'''

'''
Encrypted entry point
        |
        v
Install Hyperion loader API breakpoints
        |
        v
Observe LoadLibraryA
        |
        v
Observe GetProcAddress
        |
        v
Observe API-resolution activity
        |
        v
Identify candidate VirtualAlloc
        |
        v
Validate allocation arguments
        |
        v
Return to caller and capture RAX
        |
        v
Locate REP MOVSQ
        |
        v
Verify source, destination, and copy size
        |
        v
Track original ciphertext source
        |
        v
Detect decrypted PE headers
        |
        v
Validate recovered PE metadata
        |
        v
Extract candidate OEP RVA
        |
        v
Calculate candidate OEP VA
        |
        v
Install hardware execution breakpoint
        |
        v
Confirm execution reaches OEP
'''

from __future__ import annotations
import re
import struct

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import pefile

from runners.debugger import CdbDebugger, DebuggerError, ModuleInfo
from runners.cfg import ControlFlowAnalyzer, classify_control_flow
from runners.iat import Thunk, IATAnalysisResult
from runners.import_resolver import ResolvedImport
from runners.post_oep_recovery import PostOEPRecovery
from runners.reconstruction import ReconstructionResult

class RuntimeDecryptError(RuntimeError):
    pass

@dataclass(frozen=True)
class BootstrapEvent:
    api: str
    rip: int

@dataclass(frozen=True)
class AllocationInfo:
    base: int
    size: int
    allocation_type: int
    protection: int
    return_address: int

@dataclass(frozen=True)
class CopyInfo:
    instruction_va: int
    source_va: int
    destination_va: int
    size: int

@dataclass(frozen=True)
class RecoveredSection:
    name: str
    rva: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

@dataclass(frozen=True)
class RecoveredPE:
    buffer_va: int
    preferred_image_base: int
    image_size: int
    oep_rva: int
    sections: tuple[RecoveredSection, ...]

@dataclass(frozen=True)
class ProtectionEvent:
    address: int
    size: int
    new_protection: int
    return_address: int
    succeeded: bool = False

@dataclass(frozen=True)
class DecryptResult:
    input_path: Path
    pid: int

    encrypted_image_base: int
    encrypted_entry_rva: int

    bootstrap_events: tuple[BootstrapEvent, ...]
    protection_events: tuple[ProtectionEvent, ...]

    allocation: AllocationInfo
    copy: CopyInfo

    intermediate_pe_va: int
    recovered_image_base: int
    recovered_image_size: int

    oep_va: int
    oep_rva: int

    sections: tuple[RecoveredSection, ...]
    loaded_modules: tuple[ModuleInfo, ...]

    iat_start_va: int
    iat_size: int

    iat_valid_thunks: int
    iat_invalid_thunks: int

    iat_thunks: tuple[Thunk, ...]
    iat_analysis: IATAnalysisResult

    resolved_imports: tuple[ResolvedImport, ...]

    dump_path: Path
    reconstructed_path: Path | None

    reconstruction: ReconstructionResult | None

    @property
    def iat_rva(self) -> int:
        return self.iat_start_va - self.recovered_image_base

class RuntimeDecryptor:
    '''
    Deterministic Hyperion runtime PE recovery.

    Workflow:

        Encrypted EP
            -> API bootstrap monitoring
            -> VirtualAlloc candidate
            -> Allocation return
            -> REP MOVSQ
            -> Breakpoint after REP MOVSQ
            -> Source/decryption monitoring
            -> Recovered PE header
            -> Candidate OEP
            -> VirtualProtect monitoring
            -> OEP execution confirmation
            -> Mapped-image validation

    This workflow stops at the confirmed OEP.

    IAT rebuilding and PE reconstruction are handled by
    downstream pipeline components.
    '''

    BOOTSTRAP_APIS = ("LoadLibraryA", "GetProcAddress", "VirtualAlloc")

    EVENT_MARKERS = {
        "LoadLibraryA": "HYP_LOAD",
        "GetProcAddress": "HYP_RESOLVE",
        "VirtualAlloc": "HYP_ALLOC",
        "VirtualProtect": "HYP_PROTECT",
        "MapViewOfFile": "HYP_MAP",
        "SourceWrite": "HYP_WRITE",
        "OEP": "HYP_OEP",
    }

    def __init__(
        self,
        debugger: CdbDebugger,
        max_bootstrap_events: int = 256,
        max_copy_instructions: int = 4096,
        max_monitor_events: int = 10000,
        max_header_offset: int = 0x40):
        '''
        Initialize the Hyperion runtime decryptor.

        Parameters:
            debugger: An instance of CdbDebugger for controlling
        '''

        self.debugger = debugger

        self.max_bootstrap_events = max_bootstrap_events
        self.max_copy_instructions = max_copy_instructions
        self.max_monitor_events = max_monitor_events
        self.max_header_offset = max_header_offset

        self._previous_header_bytes = None

        self._api_breakpoint_ids: dict[str, int] = {}

    # ----------------------------------------------------------
    # Public workflow
    # ----------------------------------------------------------

    def run(self, executable: Path | str) -> DecryptResult:
        '''
        RuntimeDecryptor.run()
            |
            |-- Launch encrypted executable
            |
            |-- Identify Hyperion API bootstrap
            |
            |-- Identify VirtualAlloc
            |
            |-- Identify initial REP MOVSQ
            |
            |-- CFG-based successful-decryption breakpoint
            |
            |-- Validate recovered PE
            |
            |-- Monitor VirtualProtect
            |
            |-- Stop CDB at recovered OEP
            |
            v
        PostOEPRecovery.run()
            |
            |-- Enumerate loaded modules
            |
            |-- Discover Standard / Advanced IAT candidates
            |
            |-- Select best IAT
            |
            |-- Identify and prune invalid thunks
            |
            |-- Resolve imports
            |
            |-- Dump reconstructed image
            |
            |-- Rebuild import descriptors and thunk arrays
            |
            |-- Reconstruct disk-layout PE
            |
            |-- Patch IAT references
            |
            |-- Validate reconstructed PE
            |
            v
        DecryptResult
            |
            |-- Hyperion recovery metadata
            |-- Selected IAT metadata
            |-- Complete IAT analysis
            |-- Resolved imports
            |-- Memory dump path
            |-- Reconstructed PE path
            |-- Reconstruction result
        '''

        executable = Path(executable)

        if not executable.exists():
            raise RuntimeDecryptError(f"Executable not found: {executable}")

        pe = pefile.PE(str(executable))

        try:

            if pe.OPTIONAL_HEADER.Magic != 0x20B:
                raise RuntimeDecryptError("Expected PE32+ executable")

            encrypted_entry_rva = (pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        finally:

            pe.close()

        self.debugger.launch(executable)

        try:

            module = self.debugger.get_module(executable.name)

            image_base = module.base
            entry_va = image_base + encrypted_entry_rva

            pid = self.debugger.get_process_id()

            print(f"[hyperion] Image base: 0x{image_base:X}")

            print(f"[hyperion] Entry VA: 0x{entry_va:X}")

            # --------------------------------------------------
            # Stage 1: Stop at encrypted entry point
            # --------------------------------------------------

            self.debugger.set_breakpoint(entry_va)

            self.debugger.continue_execution()

            self._require_rip(entry_va)

            self._clear_all_breakpoints()

            # --------------------------------------------------
            # Stage 2: Observe loader bootstrap
            # --------------------------------------------------

            bootstrap_events, allocation = (
                self._observe_loader_bootstrap(image_base=image_base, image_end=module.end)
            )

            # --------------------------------------------------
            # Stage 3: Identify and complete REP MOVSQ
            # --------------------------------------------------

            copy = self._observe_bulk_copy(allocation)

            print("\n[hyperion] Initial ciphertext copy completed.")

            print(f"[hyperion] Source: " f"0x{copy.source_va:X}")

            print(f"[hyperion] Temporary allocation: " f"0x{allocation.base:X}")

                        # --------------------------------------------------
            # Stage 4: Discover successful decryption
            # --------------------------------------------------

            print("\n[hyperion] Discovering loader " "decryption success breakpoint.")

            recovered = self._await_recovered_pe_success(allocation=allocation, copy=copy)

            # --------------------------------------------------
            # Stage 5: Calculate recovered OEP
            # --------------------------------------------------

            oep_va = image_base + recovered.oep_rva

            print("\n[hyperion] Recovered PE identified.")

            print(f"[hyperion] Recovered PE VA: " f"0x{recovered.buffer_va:X}")

            print(f"[hyperion] OEP RVA: " f"0x{recovered.oep_rva:X}")

            print(f"[hyperion] Candidate runtime OEP: " f"0x{oep_va:X}")

            # --------------------------------------------------
            # Stage 6: Monitor final image reconstruction
            # --------------------------------------------------

            recovered, protection_events = (
                self._observe_decryption_and_reconstruction(
                    allocation=allocation,
                    copy=copy,
                    image_base=image_base,
                    image_end=module.end,
                    recovered=recovered)
            )

            # --------------------------------------------------
            # Stage 7: Shared post-OEP recovery
            # --------------------------------------------------

            dump_dir = Path.cwd() / "dumps"
            dump_dir.mkdir(parents=True, exist_ok=True)

            dump_path = dump_dir / f"{executable.stem}_memory.bin"
            reconstructed_path = dump_dir / f"{executable.stem}_reconstructed.exe"

            post_oep = PostOEPRecovery(self.debugger)

            post_oep_result = post_oep.run(
                image_base=image_base,
                image_size=recovered.image_size,
                oep_rva=recovered.oep_rva,
                dump_path=dump_path,
                reconstructed_path=reconstructed_path,
            )

            # --------------------------------------------------
            # Stage 8: Return OEP synchronization result
            # --------------------------------------------------

            return DecryptResult(
                input_path=executable,
                pid=pid,
                encrypted_image_base=image_base,
                encrypted_entry_rva=encrypted_entry_rva,

                bootstrap_events=bootstrap_events,
                protection_events=protection_events,

                allocation=allocation,
                copy=copy,

                intermediate_pe_va=recovered.buffer_va,
                recovered_image_base=image_base,
                recovered_image_size=recovered.image_size,

                oep_va=oep_va,
                oep_rva=recovered.oep_rva,

                sections=recovered.sections,
                loaded_modules=post_oep_result.loaded_modules,

                iat_start_va=post_oep_result.iat_start_va,
                iat_size=post_oep_result.iat_size,

                iat_valid_thunks=post_oep_result.iat_valid_thunks,
                iat_invalid_thunks=post_oep_result.iat_invalid_thunks,

                iat_thunks=post_oep_result.iat_thunks,
                iat_analysis=post_oep_result.iat_analysis,

                resolved_imports=post_oep_result.resolved_imports,

                dump_path=post_oep_result.dump_path,
                reconstructed_path=post_oep_result.reconstructed_path,

                reconstruction=post_oep_result.reconstruction,
            )

        except Exception:

            self.debugger.close()

            raise

    # ----------------------------------------------------------
    # Breakpoint management
    # ----------------------------------------------------------

    def _set_api_breakpoint(self, api: str) -> None:
        '''
        Install a named CDB API breakpoint.

        Resolve the numeric breakpoint ID from the debugger's
        breakpoint listing and store it in the API registry.

        If an existing registered breakpoint is still present,
        do not install a duplicate.
        '''

        if api in self._api_breakpoint_ids:

            breakpoint_id = self._api_breakpoint_ids[api]

            print(f"[breakpoint] {api} already registered " f"as breakpoint {breakpoint_id}")

            return

        marker = self.EVENT_MARKERS[api]

        command = (f'bu KERNELBASE!{api} ".echo {marker}"')

        output = self.debugger.command(command)

        if ("Couldn't resolve" in output or "error" in output.lower()):
            raise RuntimeDecryptError(f"Failed to install breakpoint for {api}:\n" f"{output}")

        breakpoint_id = self._find_api_breakpoint_id(api)

        self._api_breakpoint_ids[api] = breakpoint_id

        print(f"[breakpoint] Installed KERNELBASE!{api} " f"(ID={breakpoint_id})")

    def _find_api_breakpoint_id(self, api: str) -> int:
        '''
        Find the CDB breakpoint ID associated with an API.

        Query the debugger breakpoint list and identify the
        breakpoint using its unique event marker.

        Return the numeric breakpoint ID.

        Raise RuntimeDecryptError if the breakpoint cannot
        be identified unambiguously.
        '''

        marker = self.EVENT_MARKERS[api]

        output = self.debugger.command("bl")

        matches = []

        for line in output.splitlines():

            if marker not in line:
                continue

            match = re.match(r"^\s*(\d+)\s+", line)

            if match is None:
                continue

            breakpoint_id = int(match.group(1), 10)

            matches.append(breakpoint_id)

        if len(matches) != 1:

            raise RuntimeDecryptError(
                f"Expected exactly one breakpoint for {api}, "
                f"found {len(matches)}.\n"
                f"Breakpoint listing:\n{output}"
            )

        return matches[0]

    def _disable_api_breakpoint(self, api: str) -> None:
        '''
        Disable a registered API breakpoint by its CDB ID.

        Preserve all other software and hardware breakpoints.
        '''

        if api not in self._api_breakpoint_ids:

            raise RuntimeDecryptError(f"No registered breakpoint for {api}")

        breakpoint_id = self._api_breakpoint_ids[api]

        output = self.debugger.command(f"bd {breakpoint_id}")

        if "error" in output.lower():
            raise RuntimeDecryptError(f"Failed to disable {api} breakpoint:\n" f"{output}")

        print(f"[breakpoint] Disabled {api} " f"(ID={breakpoint_id})")

    def _enable_api_breakpoint(self, api: str) -> None:
        '''
        Re-enable a registered API breakpoint by its CDB ID.

        Preserve all other software and hardware breakpoints.
        '''

        if api not in self._api_breakpoint_ids:

            raise RuntimeDecryptError(f"No registered breakpoint for {api}")

        breakpoint_id = self._api_breakpoint_ids[api]

        output = self.debugger.command(f"be {breakpoint_id}")

        if "error" in output.lower():
            raise RuntimeDecryptError(f"Failed to enable {api} breakpoint:\n" f"{output}")

        print(f"[breakpoint] Enabled {api} " f"(ID={breakpoint_id})")

    def _remove_api_breakpoint(self, api: str) -> None:
        '''
        Permanently remove a registered API breakpoint.

        Use its numeric CDB breakpoint ID.

        Remove the corresponding registry entry only after
        the debugger accepts the clear command.

        Preserve all unrelated breakpoints.
        '''

        if api not in self._api_breakpoint_ids:

            raise RuntimeDecryptError(f"No registered breakpoint for {api}")

        breakpoint_id = self._api_breakpoint_ids[api]

        output = self.debugger.command(f"bc {breakpoint_id}")

        if "error" in output.lower():
            raise RuntimeDecryptError(f"Failed to remove {api} breakpoint:\n" f"{output}")

        del self._api_breakpoint_ids[api]

        print(f"[breakpoint] Removed {api} " f"(ID={breakpoint_id})")

    def _clear_all_breakpoints(self) -> None:
        '''
        Remove every debugger breakpoint and invalidate
        all locally tracked API breakpoint IDs.

        Use this method instead of calling the debugger's
        clear_all_breakpoints() directly.
        '''

        self.debugger.clear_all_breakpoints()

        self._api_breakpoint_ids.clear()

    def _set_source_breakpoint(self, source_va: int) -> None:
        '''
        Monitor writes to the first eight bytes of the
        identified ciphertext source.

        This is a targeted header watchpoint, not a
        full-region memory breakpoint.
        '''

        watch_va = source_va & ~0x7

        marker = self.EVENT_MARKERS["SourceWrite"]

        self.debugger.command(f'ba w8 0x{watch_va:X} ".echo {marker}"')

    def _set_oep_breakpoint(self, oep_va: int) -> None:
        '''
        Install a hardware execution breakpoint at the
        candidate original entry point.
        '''

        marker = self.EVENT_MARKERS["OEP"]

        self.debugger.command(f'ba e1 0x{oep_va:X} ".echo {marker}"')

    def _classify_event(self, output: str) -> str | None:
        '''
        Classify CDB breakpoint output using exact marker lines.

        A structured stop-event API would be preferable
        for production use.
        '''

        matches = []

        for api, marker in self.EVENT_MARKERS.items():
            pattern = rf"(?m)^\s*{re.escape(marker)}\s*$"

            if re.search(pattern, output):
                matches.append(api)

        if len(matches) != 1:
            return None

        return matches[0]

    # ----------------------------------------------------------
    # Bootstrap monitoring
    # ----------------------------------------------------------

    def _observe_loader_bootstrap(self, image_base: int, image_end: int) -> tuple[tuple[BootstrapEvent, ...], AllocationInfo]:
        '''
        Observe the loader's API calls and identify a candidate
        VirtualAlloc allocation associated with payload recovery.

        Unlike the previous implementation, allocation inspection
        does not depend on observing LoadLibraryA or GetProcAddress
        first.

        Candidate allocations are evaluated using:
        - requested allocation size
        - allocation type
        - initial protection
        - return address
        - whether the caller belongs to the executable image
        '''

        self._clear_all_breakpoints()

        for api in self.BOOTSTRAP_APIS:
            self._set_api_breakpoint(api)

        print("\n[bootstrap] Installed CDB breakpoints:")
        print(self.debugger.command("bl"))

        events: list[BootstrapEvent] = []

        for event_index in range(self.max_bootstrap_events):

            output = self.debugger.continue_execution()

            api = self._classify_event(output)

            if api is None:
                print("[bootstrap] Unclassified debugger stop:")
                print(output)

                raise RuntimeDecryptError("Unable to classify bootstrap debugger stop.")

            rip = self.debugger.get_register("rip")

            print(f"[bootstrap] {api}: 0x{rip:X}")

            # Keep the existing BootstrapEvent construction here
            # if your dataclass uses additional fields.
            events.append(BootstrapEvent(api=api, rip=rip))

            if api != "VirtualAlloc":
                continue

            registers = self.debugger.get_registers("rcx", "rdx", "r8", "r9", "rsp")

            requested_base = registers["rcx"]
            allocation_size = registers["rdx"]
            allocation_type = registers["r8"]
            protection = registers["r9"]

            return_address = self.debugger.read_qword(registers["rsp"])

            caller_in_image = (image_base <= return_address < image_end)

            print(
                "\n[allocation] VirtualAlloc candidate:\n"
                f"  lpAddress:         0x{requested_base:X}\n"
                f"  dwSize:            0x{allocation_size:X}\n"
                f"  flAllocationType:  0x{allocation_type:X}\n"
                f"  flProtect:         0x{protection:X}\n"
                f"  Return address:    0x{return_address:X}\n"
                f"  Caller in image:   {caller_in_image}"
            )

            # Hyperion's observed allocation uses MEM_COMMIT |
            # MEM_RESERVE and PAGE_READWRITE.
            #
            # These values are useful candidate filters, but they
            # do not independently prove payload recovery.
            matches_allocation_pattern = (
                requested_base == 0
                and allocation_size > 0
                and (allocation_type & 0x3000) == 0x3000
                and protection == 0x04
            )

            if not matches_allocation_pattern:
                print("[allocation] Candidate rejected: " "allocation arguments do not match.")
                continue

            if not caller_in_image:
                print("[allocation] Candidate rejected: " "caller is outside the executable image.")
                continue

            print("[allocation] Candidate matches. " "Waiting for VirtualAlloc return.")

            self.debugger.command("gu", timeout=120.0)

            return_rip = self.debugger.get_register("rip")

            print(f"[allocation] Expected return RIP: " f"0x{return_address:X}")

            print(f"[allocation] Actual return RIP:   " f"0x{return_rip:X}")

            if return_rip != return_address:
                raise RuntimeDecryptError(
                    "VirtualAlloc did not return to the expected caller. "
                    f"Expected 0x{return_address:X}, "
                    f"got 0x{return_rip:X}"
                )

            allocated_base = self.debugger.get_register("rax")

            print(f"[allocation] VirtualAlloc returned: " f"0x{allocated_base:X}")

            if allocated_base == 0:
                print("[allocation] Candidate rejected: " "VirtualAlloc failed.")
                continue

            # Construct AllocationInfo using the field names
            # from your existing dataclass.
            allocation = AllocationInfo(
                base=allocated_base,
                size=allocation_size,
                allocation_type=allocation_type,
                protection=protection,
                return_address=return_address)

            self._clear_all_breakpoints()

            return tuple(events), allocation

        raise RuntimeDecryptError(
            "Bootstrap event limit reached without identifying "
            "a suitable VirtualAlloc allocation."
        )

    # ----------------------------------------------------------
    # REP MOVSQ detection
    # ----------------------------------------------------------

    def _observe_bulk_copy(self, allocation: AllocationInfo) -> CopyInfo:
        '''
        Follow execution after VirtualAlloc returns.

        Identify the REP MOVSQ instruction using its machine-code
        encoding rather than relying exclusively on debugger
        disassembly formatting.

        Validate:
            - destination matches the observed allocation
            - copy size matches the allocation size
            - source and destination are nonzero

        Once identified, stop immediately after the copy and
        validate the resulting register state.
        '''

        for instruction_index in range(self.max_copy_instructions):
            rip = self.debugger.get_register("rip")

            instruction = self.debugger.disassemble_one(rip)

            mnemonic = instruction.mnemonic.lower()
            operands = instruction.operands.lower()

            raw_bytes = instruction.raw_bytes

            # REP MOVSQ:
            #
            # F3 = REP
            # 48 = REX.W
            # A5 = MOVS
            #
            # The debugger may display this as:
            #
            #   rep movs qword ptr [rdi], qword ptr [rsi]
            #
            # rather than:
            #
            #   rep movsq

            is_rep_movsq = (raw_bytes.startswith(b"\xF3\x48\xA5") or raw_bytes.startswith(b"\x48\xF3\xA5"))

            if instruction_index < 30:
                print(
                    f"[copy-trace] "
                    f"{instruction_index:04d} "
                    f"0x{rip:X}: "
                    f"{mnemonic} {operands} "
                    f"bytes={raw_bytes.hex()}"
                )

            if not is_rep_movsq:
                self.debugger.command("p")
                continue

            print(f"\n[copy] REP MOVSQ detected at 0x{rip:X}")

            registers = self.debugger.get_registers("rsi", "rdi", "rcx")

            source_va = registers["rsi"]
            destination_va = registers["rdi"]
            copy_size = registers["rcx"] * 8

            print(
                "\n[copy] Candidate details:\n"
                f"  Instruction:  0x{rip:X}\n"
                f"  Source:       0x{source_va:X}\n"
                f"  Destination:  0x{destination_va:X}\n"
                f"  RCX:          0x{registers['rcx']:X}\n"
                f"  Copy size:    0x{copy_size:X}\n"
                f"  Alloc base:   0x{allocation.base:X}\n"
                f"  Alloc size:   0x{allocation.size:X}"
            )

            if destination_va != allocation.base:
                print("[copy] Candidate rejected: " "destination does not match allocation.")

                self.debugger.command("p")
                continue

            if copy_size != allocation.size:
                print("[copy] Candidate rejected: " "copy size does not match allocation.")

                self.debugger.command("p")
                continue

            if source_va == 0 or destination_va == 0:
                raise RuntimeDecryptError("REP MOVSQ has an invalid source or destination.")

            print("\n[copy] Matching REP MOVSQ confirmed.")

            self._complete_bulk_copy(
                instruction_va=rip,
                source_va=source_va,
                destination_va=destination_va,
                copy_size=copy_size)

            return CopyInfo(
                instruction_va=rip,
                source_va=source_va,
                destination_va=destination_va,
                size=copy_size)

        raise RuntimeDecryptError(
            "Matching REP MOVSQ not found within "
            f"{self.max_copy_instructions} instructions."
        )

    def _complete_bulk_copy(self, instruction_va: int, source_va: int, destination_va: int, copy_size: int) -> None:
        '''
        Reproduce the manual x64dbg workflow:

        1. Identify the instruction after REP MOVSQ.
        2. Set a software breakpoint at that address.
        3. Continue execution.
        4. Validate completion using RCX, RSI, and RDI.
        '''

        instruction = self.debugger.disassemble_one(instruction_va)

        next_va = (instruction_va + len(instruction.raw_bytes))

        self._clear_all_breakpoints()

        self.debugger.set_breakpoint(next_va)

        print(f"[copy] Completion breakpoint: 0x{next_va:X}")

        self.debugger.continue_execution()

        self._require_rip(next_va)

        registers = self.debugger.get_registers("rcx", "rsi", "rdi")

        if registers["rcx"] != 0:
            raise RuntimeDecryptError("REP MOVSQ did not complete")

        if registers["rsi"] != source_va + copy_size:
            raise RuntimeDecryptError("Unexpected final RSI")

        if registers["rdi"] != destination_va + copy_size:
            raise RuntimeDecryptError("Unexpected final RDI")

        self._clear_all_breakpoints()

        print("[copy] Bulk copy completed")

    def _wait_for_allocation_clear(self, allocation: AllocationInfo, copy: CopyInfo) -> None:
        '''
        Wait for a write to the temporary allocation after the
        initial REP MOVSQ ciphertext copy has completed.

        Reproduce the manual x64dbg workflow:

            1. Stop at the instruction after REP MOVSQ.
            2. Confirm the allocation contains copied ciphertext.
            3. Install a write breakpoint on the allocation.
            4. Continue execution.
            5. Detect when the monitored bytes become zero.
            6. Return so PE reconstruction monitoring can begin.

        The breakpoint monitors the first eight bytes of the
        allocation, not the entire allocation.
        '''

        if allocation.base == 0:
            raise RuntimeDecryptError("Cannot monitor an invalid allocation address.")

        if allocation.size < 8:
            raise RuntimeDecryptError("Allocation is too small for an eight-byte watchpoint.")

        if copy.destination_va != allocation.base:
            raise RuntimeDecryptError("Copy destination does not match the allocation base.")

        watch_va = allocation.base

        sample_size = min(allocation.size, 64)

        def read_allocation_sample() -> bytes:
            '''
            Read the beginning of the temporary allocation.
            '''

            with TemporaryDirectory() as directory:

                path = Path(directory) / "allocation_sample.bin"

                self.debugger.write_memory(
                    output_path=path,
                    start_va=allocation.base,
                    end_va=allocation.base + sample_size)

                data = path.read_bytes()

            if len(data) != sample_size:
                raise RuntimeDecryptError(
                    "Failed to read the expected allocation sample. "
                    f"Expected {sample_size} bytes, got {len(data)}."
                )

            return data

        # --------------------------------------------------
        # Step 1: Capture allocation contents after REP MOVSQ
        # --------------------------------------------------

        print("\n[allocation-monitor] Initial ciphertext copy completed.")

        print(f"[allocation-monitor] Allocation base: " f"0x{allocation.base:X}")

        print(f"[allocation-monitor] Allocation size: " f"0x{allocation.size:X}")

        initial_sample = read_allocation_sample()

        print("[allocation-monitor] Initial allocation bytes:\n" f"  {initial_sample.hex(' ')}")

        if not any(initial_sample):
            raise RuntimeDecryptError(
                "Temporary allocation is already zero at the "
                "post-REP MOVSQ checkpoint."
            )

        # --------------------------------------------------
        # Step 2: Install write breakpoint
        # --------------------------------------------------

        self._clear_all_breakpoints()

        breakpoint_output = self.debugger.command(f"ba w8 0x{watch_va:X}")

        if ("error" in breakpoint_output.lower() or "couldn't" in breakpoint_output.lower()):
            raise RuntimeDecryptError(
                "Failed to install allocation write breakpoint:\n"
                f"{breakpoint_output}"
            )

        print(
            "[allocation-monitor] Write breakpoint installed:\n"
            f"  Address: 0x{watch_va:X}\n"
            "  Size:    8 bytes"
        )

        # --------------------------------------------------
        # Step 3: Wait for the allocation to change
        # --------------------------------------------------

        previous_sample = initial_sample

        try:

            for event_number in range(self.max_monitor_events):

                self.debugger.continue_execution()

                rip = self.debugger.get_register("rip")

                current_sample = read_allocation_sample()

                if current_sample != previous_sample:

                    changed_offsets = [
                        index
                        for index, (old, new) in enumerate(zip(previous_sample, current_sample))
                        if old != new
                    ]

                    print("\n[allocation-monitor] Allocation modified.")

                    print(f"[allocation-monitor] Event: " f"{event_number + 1}")

                    print(f"[allocation-monitor] RIP: 0x{rip:X}")

                    print(
                        "[allocation-monitor] Changed offsets: "
                        + ", ".join(f"0x{offset:X}" for offset in changed_offsets)
                    )

                    print("[allocation-monitor] Current bytes:\n" f"  {current_sample.hex(' ')}")

                # --------------------------------------------------
                # Step 4: Detect the zeroed allocation
                # --------------------------------------------------

                if not any(current_sample):

                    print("\n[allocation-monitor] Allocation sample " "is now zero.")

                    print(f"[allocation-monitor] Event: " f"{event_number + 1}")

                    print(f"[allocation-monitor] RIP: 0x{rip:X}")

                    print("[allocation-monitor] Temporary allocation " "transition detected.")

                    recovered = self._parse_recovered_pe(copy.source_va, copy.size)
                    
                    if recovered is not None:
        
                        print(
                            "[allocation-monitor] Recovered PE detected "
                            "immediately after allocation clearing."
                        )
        
                        print(f"[allocation-monitor] PE VA: " f"0x{recovered.buffer_va:X}")
        
                        print(f"[allocation-monitor] OEP RVA: " f"0x{recovered.oep_rva:X}")
        
                    else:
        
                        print(
                            "[allocation-monitor] Allocation cleared, "
                            "but a valid recovered PE was not detected yet."
                        )

                    return

                previous_sample = current_sample

            raise RuntimeDecryptError(
                "Temporary allocation did not become zero within "
                f"{self.max_monitor_events} write-breakpoint events."
            )

        finally:

            self._clear_all_breakpoints()

    def _relative_branch_target(self, instruction_va: int, raw_bytes: bytes) -> tuple[int, str] | None:
        '''
        Decode the destination of a direct relative x64 branch.

        Supported encodings:

            EB cb           JMP rel8
            E9 cd           JMP rel32
            70-7F cb        Jcc rel8
            0F 80-8F cd     Jcc rel32

        Return:

            (destination_va, branch_type)

        Branch types:

            "jmp"          Unconditional branch
            "conditional"  Conditional branch

        Return None for unsupported instructions.

        Indirect branches are intentionally not decoded.
        '''

        if not raw_bytes:
            return None

        opcode = raw_bytes[0]

        # --------------------------------------------------
        # Short unconditional JMP
        # --------------------------------------------------

        if opcode == 0xEB and len(raw_bytes) == 2:

            displacement = struct.unpack_from("<b", raw_bytes, 1)[0]

            destination = (instruction_va + len(raw_bytes) + displacement)

            return destination, "jmp"

        # --------------------------------------------------
        # Near unconditional JMP
        # --------------------------------------------------

        if opcode == 0xE9 and len(raw_bytes) == 5:

            displacement = struct.unpack_from("<i", raw_bytes, 1)[0]

            destination = (instruction_va + len(raw_bytes) + displacement)

            return destination, "jmp"

        # --------------------------------------------------
        # Short conditional branch
        # --------------------------------------------------

        if 0x70 <= opcode <= 0x7F and len(raw_bytes) == 2:

            displacement = struct.unpack_from("<b", raw_bytes, 1)[0]

            destination = (instruction_va + len(raw_bytes) + displacement)

            return destination, "conditional"

        # --------------------------------------------------
        # Near conditional branch
        # --------------------------------------------------

        if (len(raw_bytes) == 6 and raw_bytes[0] == 0x0F and 0x80 <= raw_bytes[1] <= 0x8F):

            displacement = struct.unpack_from("<i", raw_bytes, 2)[0]

            destination = (instruction_va + len(raw_bytes) + displacement)

            return destination, "conditional"

        return None

    def _discover_decryption_success_breakpoint(
        self,
        allocation: AllocationInfo,
        copy: CopyInfo,
        max_scan_bytes: int = 0x600) -> int:
        '''
        Discover the Hyperion loader's successful-decryption
        branch using the existing ControlFlowAnalyzer.

        Starting immediately after the initial ciphertext
        backup operation, construct a bounded CFG and identify
        a structure containing:

            1. A conditional validation branch.
            2. A failure path containing REP MOVSQ restoration.
            3. A backward unconditional retry jump.
            4. An acceptance path that bypasses restoration.

        The acceptance destination is returned as the
        decryption-success breakpoint.

        This method performs structural CFG analysis only.
        Recovered PE validation occurs after the debugger
        reaches the selected breakpoint.
        '''

        # --------------------------------------------------
        # Step 1: Identify CFG analysis bounds
        # --------------------------------------------------

        initial_copy = self.debugger.disassemble_one(copy.instruction_va)

        scan_start = copy.instruction_va + initial_copy.size
        scan_end = scan_start + max_scan_bytes

        print("\n[decrypt-discovery] Building loader CFG.")
        print(f"[decrypt-discovery] Initial copy: 0x{copy.instruction_va:X}")
        print(f"[decrypt-discovery] CFG entry: 0x{scan_start:X}")
        print(f"[decrypt-discovery] CFG end: 0x{scan_end:X}")
        print(f"[decrypt-discovery] Source: 0x{copy.source_va:X}")
        print(f"[decrypt-discovery] Temporary allocation: 0x{allocation.base:X}")

        # --------------------------------------------------
        # Step 2: Build control-flow graph
        # --------------------------------------------------

        analyzer = ControlFlowAnalyzer(
            debugger=self.debugger,
            max_instructions=1000
        )

        graph = analyzer.analyze(
            entry_va=scan_start,
            start_va=scan_start,
            end_va=scan_end
        )

        print(f"[decrypt-discovery] Instructions: {len(graph.instructions)}")
        print(f"[decrypt-discovery] Unresolved: {len(graph.unresolved)}")
        print(f"[decrypt-discovery] Decode errors: {len(graph.decode_errors)}")
        print(f"[decrypt-discovery] Truncated: {graph.truncated}")

        if not graph.instructions:
            raise RuntimeDecryptError("CFG analysis returned no instructions.")

        if graph.truncated:
            raise RuntimeDecryptError(
                "CFG analysis exceeded its instruction budget. "
                "Cannot reliably identify the acceptance branch."
            )

        # --------------------------------------------------
        # Step 3: Identify ciphertext restoration operations
        # --------------------------------------------------

        restoration_candidates = []

        for address, instruction in graph.instructions.items():
            raw = instruction.raw_bytes

            is_rep_movsq = (
                raw.startswith(b"\xF3\x48\xA5")
                or raw.startswith(b"\x48\xF3\xA5")
            )

            if not is_rep_movsq:
                continue

            if address == copy.instruction_va:
                continue

            restoration_candidates.append(address)

        if not restoration_candidates:
            raise RuntimeDecryptError(
                "No ciphertext-restoration REP MOVSQ "
                "was discovered in the loader CFG."
            )

        print(f"[decrypt-discovery] Restoration candidates: {len(restoration_candidates)}")

        # --------------------------------------------------
        # Step 4: Identify backward retry jumps
        # --------------------------------------------------

        retry_candidates = []

        for address, instruction in graph.instructions.items():
            flow = classify_control_flow(instruction)

            if flow.kind != "unconditional_jump":
                continue

            target = flow.branch_target

            if target is None:
                continue

            if target >= address:
                continue

            if target not in graph.instructions:
                continue

            retry_candidates.append({
                "jump_va": address,
                "target_va": target
            })

        print(f"[decrypt-discovery] Backward jumps: {len(retry_candidates)}")

        # --------------------------------------------------
        # Step 5: Graph reachability helper
        # --------------------------------------------------

        def is_reachable(start: int, destination: int, blocked: set[int] | None = None) -> bool:
            '''
            Determine whether destination is reachable from
            start using decoded CFG edges.

            Optional blocked addresses prevent traversal
            through competing paths.
            '''

            blocked = blocked or set()
            pending = [start]
            visited = set()

            while pending:
                address = pending.pop()

                if address in blocked or address in visited:
                    continue

                if address == destination:
                    return True

                visited.add(address)

                for successor in graph.edges.get(address, set()):
                    if successor not in visited and successor not in blocked:
                        pending.append(successor)

            return False

        # --------------------------------------------------
        # Step 6: Identify validation-branch candidates
        # --------------------------------------------------

        acceptance_candidates = []

        for branch_va, instruction in graph.instructions.items():
            flow = classify_control_flow(instruction)

            if flow.kind != "conditional_jump":
                continue

            if flow.branch_target is None or flow.fallthrough is None:
                continue

            branch_successors = graph.edges.get(branch_va, set())

            if len(branch_successors) != 2:
                continue

            for restoration_va in restoration_candidates:

                # The validation branch must precede restoration.
                if branch_va >= restoration_va:
                    continue

                # The failure path must reach restoration.
                failure_successors = [
                    successor
                    for successor in branch_successors
                    if is_reachable(successor, restoration_va)
                ]

                if len(failure_successors) != 1:
                    continue

                failure_va = failure_successors[0]

                # The other successor is the acceptance candidate.
                acceptance_va = next(
                    successor
                    for successor in branch_successors
                    if successor != failure_va
                )

                # The acceptance path must bypass restoration.
                if acceptance_va <= restoration_va:
                    continue

                if acceptance_va not in graph.instructions:
                    continue

                # The failure path must contain a backward retry.
                for retry in retry_candidates:
                    retry_va = retry["jump_va"]
                    retry_target = retry["target_va"]

                    if retry_va <= restoration_va:
                        continue

                    if retry_va >= acceptance_va:
                        continue

                    if retry_target >= branch_va:
                        continue

                    if not is_reachable(
                        restoration_va,
                        retry_va,
                        blocked={acceptance_va}
                    ):
                        continue

                    # Retry should return to code that can
                    # reach the validation branch again.
                    if not is_reachable(
                        retry_target,
                        branch_va,
                        blocked={acceptance_va}
                    ):
                        continue

                    acceptance_candidates.append({
                        "acceptance_va": acceptance_va,
                        "branch_va": branch_va,
                        "failure_va": failure_va,
                        "restoration_va": restoration_va,
                        "retry_va": retry_va,
                        "retry_target": retry_target
                    })

        # --------------------------------------------------
        # Step 7: Deduplicate candidates
        # --------------------------------------------------

        unique_candidates = {}

        for candidate in acceptance_candidates:
            unique_candidates.setdefault(candidate["acceptance_va"], candidate)

        candidates = list(unique_candidates.values())

        # --------------------------------------------------
        # Step 8: Require an unambiguous acceptance path
        # --------------------------------------------------

        if not candidates:
            raise RuntimeDecryptError(
                "Unable to discover a successful-decryption "
                "branch from the loader CFG."
            )

        if len(candidates) != 1:
            addresses = ", ".join(
                f"0x{candidate['acceptance_va']:X}"
                for candidate in candidates
            )

            raise RuntimeDecryptError(
                "Ambiguous decryption acceptance candidates: " + addresses
            )

        candidate = candidates[0]
        acceptance_va = candidate["acceptance_va"]

        print("\n[decrypt-discovery] Acceptance candidate identified.")
        print(f"  Validation branch: 0x{candidate['branch_va']:X}")
        print(f"  Failure successor: 0x{candidate['failure_va']:X}")
        print(f"  Restoration: 0x{candidate['restoration_va']:X}")
        print(f"  Retry jump: 0x{candidate['retry_va']:X}")
        print(f"  Retry destination: 0x{candidate['retry_target']:X}")
        print(f"  Acceptance destination: 0x{acceptance_va:X}")

        return acceptance_va

    def _await_recovered_pe_success(self, allocation: AllocationInfo, copy: CopyInfo) -> RecoveredPE:
        '''
        Synchronize with successful Hyperion runtime decryption.

        Workflow:

            1. Discover the loader decryption success breakpoint.
            2. Install a software execution breakpoint.
            3. Continue execution through transformation attempts.
            4. Stop at the decrypted-transformation path.
            5. Validate the recovered PE in the original source.
            6. Return recovered PE metadata.

        The recovered PE is not dumped here.

        Its metadata will be used to identify the final runtime
        OEP and continue execution until that OEP is reached.
        '''

        # --------------------------------------------------
        # Step 1: Discover decryption success breakpoint
        # --------------------------------------------------

        decrypt_success_va = self._discover_decryption_success_breakpoint(allocation=allocation, copy=copy)

        # --------------------------------------------------
        # Step 2: Install breakpoint
        # --------------------------------------------------

        self._clear_all_breakpoints()

        self.debugger.set_breakpoint(decrypt_success_va)

        print("\n[decrypt] Waiting for decrypted " "transformation.")

        print(f"[decrypt] Decryption success breakpoint: " f"0x{decrypt_success_va:X}")

        # --------------------------------------------------
        # Step 3: Continue through decryption attempts
        # --------------------------------------------------

        self.debugger.continue_execution()

        # --------------------------------------------------
        # Step 4: Confirm expected execution location
        # --------------------------------------------------

        self._require_rip(decrypt_success_va)

        print("\n[decrypt] Decryption success " "breakpoint reached.")

        # --------------------------------------------------
        # Step 5: Validate recovered PE
        # --------------------------------------------------

        recovered = self._parse_recovered_pe(source_va=copy.source_va, source_size=copy.size)

        if recovered is None:

            raise RuntimeDecryptError(
                "Decryption success breakpoint was reached, "
                "but the original source buffer does not "
                "contain a structurally valid recovered PE."
            )

        # --------------------------------------------------
        # Step 6: Report recovered metadata
        # --------------------------------------------------

        print("\n[decrypt] Reconstructed PE validated.")

        print(f"[decrypt] Original source: " f"0x{copy.source_va:X}")

        print(f"[decrypt] Recovered PE VA: " f"0x{recovered.buffer_va:X}")

        print(f"[decrypt] Preferred ImageBase: " f"0x{recovered.preferred_image_base:X}")

        print(f"[decrypt] SizeOfImage: " f"0x{recovered.image_size:X}")

        print(f"[decrypt] OEP RVA: " f"0x{recovered.oep_rva:X}")

        # --------------------------------------------------
        # Step 7: Remove decryption success breakpoint
        # --------------------------------------------------

        self._clear_all_breakpoints()

        return recovered

    # ----------------------------------------------------------
    # Combined decryption and reconstruction monitoring
    # ----------------------------------------------------------

    def _observe_decryption_and_reconstruction(
        self,
        allocation: AllocationInfo,
        copy: CopyInfo,
        image_base: int,
        image_end: int,
        recovered: RecoveredPE) -> tuple[RecoveredPE, tuple[ProtectionEvent, ...]]:
        '''
        Monitor final image reconstruction after successful
        Hyperion runtime decryption.

        The recovered PE has already been validated at the
        loader acceptance breakpoint.

        Workflow:

            1. Calculate candidate runtime OEP.
            2. Install a hardware execution breakpoint.
            3. Monitor VirtualProtect calls.
            4. Record completed protection changes.
            5. Continue until execution reaches the OEP.
            6. Validate the final mapped image.

        The debugger remains paused at the OEP when this
        method returns successfully.
        '''

        oep_va = image_base + recovered.oep_rva

        if not (image_base <= oep_va < image_end):
            raise RuntimeDecryptError("Candidate OEP falls outside the loaded image.")

        protection_events = []

        executable_protections = {0x10, 0x20, 0x40, 0x80, }

        # --------------------------------------------------
        # Step 1: Install reconstruction breakpoints
        # --------------------------------------------------

        self._clear_all_breakpoints()

        self._set_api_breakpoint("VirtualProtect")

        self._set_oep_breakpoint(oep_va)

        print("\n[reconstruction] Monitoring final image.")

        print(f"[reconstruction] OEP breakpoint: " f"0x{oep_va:X}")

        # --------------------------------------------------
        # Step 2: Process debugger events
        # --------------------------------------------------

        for event_number in range(self.max_monitor_events):

            output = self.debugger.continue_execution()

            event = self._classify_event(output)

            if event is None:

                raise RuntimeDecryptError("Unclassified reconstruction stop:\n" + output[-1500:])

            # --------------------------------------------------
            # OEP reached
            # --------------------------------------------------

            if event == "OEP":

                self._require_rip(oep_va)

                print("\n[oep] Original entry point reached.")

                print(f"[oep] RIP: 0x{oep_va:X}")

                self._validate_mapped_image(image_base=image_base, recovered=recovered)

                self._clear_all_breakpoints()

                print("[oep] Final mapped image validated.")

                return (recovered, tuple(protection_events))

            # --------------------------------------------------
            # VirtualProtect observed
            # --------------------------------------------------

            if event == "VirtualProtect":

                request = self._capture_virtual_protect()

                # Temporarily remove breakpoints before
                # stepping out of VirtualProtect.
                #
                # This preserves the behavior of the existing
                # debugger integration.

                self._disable_api_breakpoint("VirtualProtect")

                self.debugger.command("gu", timeout=120.0)

                self._enable_api_breakpoint("VirtualProtect")

                self._require_rip(request.return_address)

                succeeded = (self.debugger.get_register("rax") != 0)

                completed = ProtectionEvent(
                    address=request.address,
                    size=request.size,
                    new_protection=request.new_protection,
                    return_address=request.return_address,
                    succeeded=succeeded)

                protection_events.append(completed)

                if succeeded:

                    print(
                        "[protect] "
                        f"0x{completed.address:X} "
                        f"size=0x{completed.size:X} "
                        f"protect=0x{completed.new_protection:X}"
                    )

                # --------------------------------------------------
                # Determine whether OEP protection changed
                # --------------------------------------------------

                oep_region_modified = (
                    succeeded
                    and completed.address <= oep_va
                    < completed.address + completed.size
                )

                if oep_region_modified:

                    protection_base = (completed.new_protection & 0xFF)

                    is_executable = (protection_base in executable_protections)

                    print("[protect] OEP region modified.")

                    print(f"  OEP: 0x{oep_va:X}")

                    print(f"  Protection: " f"0x{completed.new_protection:X}")

                    print(f"  Executable: {is_executable}")


                continue

            raise RuntimeDecryptError(f"Unexpected reconstruction event: {event}")

        raise RuntimeDecryptError("OEP was not reached within the " "configured monitoring event limit.") 

    # ----------------------------------------------------------
    # VirtualProtect handling
    # ----------------------------------------------------------

    def _capture_virtual_protect(self) -> ProtectionEvent:
        '''
        Windows x64 VirtualProtect arguments:

            RCX = lpAddress
            RDX = dwSize
            R8  = flNewProtect
            R9  = lpflOldProtect

        RAX is inspected separately after returning.
        '''

        registers = self.debugger.get_registers("rcx", "rdx", "r8", "rsp")

        return ProtectionEvent(
            address=registers["rcx"],
            size=registers["rdx"],
            new_protection=registers["r8"],
            return_address=self.debugger.read_qword(registers["rsp"]))

    def _protection_overlaps_image(self, event: ProtectionEvent, image_base: int, image_size: int) -> bool:
        image_end = image_base + image_size

        protection_end = (event.address + event.size)

        return (event.address < image_end and protection_end > image_base)

    # ----------------------------------------------------------
    # PE header recovery
    # ----------------------------------------------------------

    def _parse_recovered_pe(self, source_va: int, source_size: int) -> RecoveredPE | None:
        '''
        Parse a recovered PE near the beginning of the known
        ciphertext source region.

        A small offset is permitted because the observed
        ransomware sample places MZ at source + 0x4.

        This is not an unrestricted memory scan.

        Validate the PE structure without requiring the OEP
        section to be marked executable.

        Runtime execution permissions are monitored separately
        through VirtualProtect events.
        '''

        header_size = min(source_size, 0x2000)

        if header_size < 0x200:
            return None

        with TemporaryDirectory() as directory:

            path = Path(directory) / "headers.bin"

            self.debugger.write_memory(output_path=path, start_va=source_va, end_va=source_va + header_size)

            data = path.read_bytes()

            # Capture the first 64 bytes of the source region.
            current_header_bytes = data[:64]

            # Only print when the bytes differ from the previous snapshot.
            if current_header_bytes != self._previous_header_bytes:

                if self._previous_header_bytes is None:
                    print("[pe-debug] Initial header snapshot")

                else:
                    print("[pe-debug] Header bytes changed")

                    # Identify which byte offsets changed.
                    changed_offsets = [
                        index
                        for index, (old, new) in enumerate(
                            zip(self._previous_header_bytes, current_header_bytes)
                        )
                        if old != new
                    ]

                    print(
                        "[pe-debug] Changed offsets: "
                        + ", ".join(f"0x{offset:X}" for offset in changed_offsets)
                    )

                print(f"[pe-debug] Source VA: 0x{source_va:X}")

                print("[pe-debug] Header bytes: " f"{current_header_bytes.hex(' ')}")

                # Save this snapshot for the next comparison.
                self._previous_header_bytes = current_header_bytes
        # --------------------------------------------------
        # Detect candidate DOS headers
        # --------------------------------------------------

        candidate_offsets = [
            offset
            for offset in range(min(self.max_header_offset + 1, max(0, len(data) - 1)))
            if data[offset:offset + 2] == b"MZ"
        ]

        if candidate_offsets:

            print("[pe-debug] MZ candidate(s): " + ", ".join(f"0x{offset:X}" for offset in candidate_offsets))

            print("[pe-debug] First 64 bytes: " f"{data[:64].hex(' ')}")

        # --------------------------------------------------
        # Locate a valid DOS/NT header
        # --------------------------------------------------

        pe_offset = self._find_recovered_pe_offset(data)

        if pe_offset is None:
            return None

        print("[pe-debug] Valid DOS/NT header " f"at offset 0x{pe_offset:X}")

        recovered_pe_va = source_va + pe_offset

        data = data[pe_offset:]

        # --------------------------------------------------
        # Parse DOS header
        # --------------------------------------------------

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

        if e_lfanew + 0x18 > len(data):
            return None

        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None

        # --------------------------------------------------
        # Parse NT headers
        # --------------------------------------------------

        optional_offset = e_lfanew + 0x18

        if optional_offset + 0x40 > len(data):
            return None

        magic = struct.unpack_from("<H", data, optional_offset)[0]

        if magic != 0x20B:
            return None

        number_of_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]

        optional_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]

        oep_rva = struct.unpack_from("<I", data, optional_offset + 0x10)[0]

        preferred_base = struct.unpack_from("<Q", data, optional_offset + 0x18)[0]

        image_size = struct.unpack_from("<I", data, optional_offset + 0x38)[0]

        section_table = (optional_offset + optional_size)

        # --------------------------------------------------
        # Validate PE metadata
        # --------------------------------------------------

        if not (0 < number_of_sections <= 96):
            return None

        if not (0 < oep_rva < image_size):
            return None

        if (section_table + number_of_sections * 40 > len(data)):
            return None

        # --------------------------------------------------
        # Parse section headers
        # --------------------------------------------------

        sections = []

        for index in range(number_of_sections):

            offset = section_table + index * 40

            name = (data[offset:offset + 8] .rstrip(b"\x00") .decode("ascii", errors="replace"))

            virtual_size, rva, raw_size, raw_offset = (struct.unpack_from("<IIII", data, offset + 8))

            characteristics = struct.unpack_from("<I", data, offset + 36)[0]

            if rva >= image_size:
                return None

            if (rva + max(virtual_size, raw_size) > image_size):
                return None

            sections.append(
                RecoveredSection(
                    name=name,
                    rva=rva,
                    virtual_size=virtual_size,
                    raw_size=raw_size,
                    raw_offset=raw_offset,
                    characteristics=characteristics)
            )

        # --------------------------------------------------
        # Validate OEP section membership
        # --------------------------------------------------

        oep_section = next(
            (
                section
                for section in sections
                if section.rva <= oep_rva
                < section.rva + max(section.virtual_size, section.raw_size)
            ),
            None)

        if oep_section is None:
            return None

        print(
            f"[pe] OEP RVA: 0x{oep_rva:X}\n"
            f"[pe] OEP section: {oep_section.name}\n"
            f"[pe] Section characteristics: "
            f"0x{oep_section.characteristics:X}\n"
            f"[pe] Section marked executable: "
            f"{oep_section.executable}"
        )

        # --------------------------------------------------
        # Return recovered PE metadata
        # --------------------------------------------------

        return RecoveredPE(
            buffer_va=recovered_pe_va,
            preferred_image_base=preferred_base,
            image_size=image_size,
            oep_rva=oep_rva,
            sections=tuple(sections))

    def _find_recovered_pe_offset(self, data: bytes) -> int | None:
        '''
        Identify a valid DOS/NT header within the first
        max_header_offset bytes of the known source.
        '''

        max_offset = min(self.max_header_offset, len(data) - 0x200)

        for offset in range(max_offset + 1):
            if data[offset:offset + 2] != b"MZ":
                continue

            e_lfanew = struct.unpack_from("<I", data, offset + 0x3C)[0]

            nt_offset = offset + e_lfanew

            if nt_offset + 0x18 > len(data):
                continue

            if (data[nt_offset:nt_offset + 4] != b"PE\x00\x00"):
                continue

            return offset

        return None

    # ----------------------------------------------------------
    # Final mapped-image validation
    # ----------------------------------------------------------

    def _validate_mapped_image(self, image_base: int, recovered: RecoveredPE) -> None:
        '''
        Validate that execution reached the candidate OEP
        and that the mapped image contains compatible PE
        metadata.

        This is a structural check, not a full comparison
        of every recovered section byte.
        '''

        mapped = self._parse_recovered_pe(
            source_va=image_base,
            source_size=min(recovered.image_size, 0x2000))

        if mapped is None:
            raise RuntimeDecryptError("Mapped image PE headers not validated")

        if mapped.oep_rva != recovered.oep_rva:
            raise RuntimeDecryptError("Mapped image OEP differs from recovered PE")

        if mapped.image_size != recovered.image_size:
            raise RuntimeDecryptError("Mapped image size differs from recovered PE")

        print("[validate] Mapped PE headers verified")

    # ----------------------------------------------------------
    # Validation helpers
    # ----------------------------------------------------------

    def _require_rip(self, expected_va: int) -> None:
        actual_va = self.debugger.get_register("rip")

        if actual_va != expected_va:
            raise RuntimeDecryptError(
                f"Unexpected RIP: "
                f"expected 0x{expected_va:X}, "
                f"got 0x{actual_va:X}"
            )